#include "switchbot_keypad_bridge.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

#include <esp_mac.h>
#include <esp_random.h>
#include <psa/crypto.h>

#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "ble_utils.h"
#include "keypad_advert.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge";

// BLE service / characteristic UUIDs as exposed by a real SwitchBot Lock.
constexpr const char *SERVICE_UUID = "cba20d00-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *RX_CHAR_UUID = "cba20002-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *TX_CHAR_UUID = "cba20003-224d-11e6-9fb8-0002a5d5c51b";

// SwitchBot's OUI. Applied to the chip's factory MAC at boot so the bridge
// advertises within SwitchBot's address range — the Keypad Vision filters
// scan results on this prefix.
constexpr uint8_t SPOOFED_OUI[3] = {0xB0, 0xE9, 0xFE};

// Manufacturer-specific advertising blob published by the genuine lock.
constexpr uint8_t ADVERTISING_MFG_DATA[] = {0x27, 0x09, 0x00, 0x10,
                                            0xA5, 0xB8, 0x00, 0x00, 0x00};

// Encrypted response payloads sent back to the keypad on lock/unlock.
constexpr uint8_t RESPONSE_LOCK[5]   = {0x90, 0x0A, 0x7F, 0x7F, 0x00};
constexpr uint8_t RESPONSE_UNLOCK[5] = {0x98, 0x08, 0x7F, 0x7F, 0x00};

// Trailing 13 bytes appended to the lock-state byte when answering a state poll.
constexpr uint8_t STATE_PAYLOAD_TAIL[13] = {0x08, 0x08, 0x41, 0x00, 0x00, 0x00, 0x00,
                                            0x80, 0xF2, 0xFB, 0x00, 0x00, 0x00};

constexpr size_t AES_KEY_SIZE = 16;

// Battery advert scan: one short active window per interval.
constexpr uint32_t BATTERY_SCAN_DURATION_MS = 5000;
constexpr uint32_t BATTERY_SCAN_RETRY_MS    = 30000;

}  // namespace

// ---------------------------------------------------------------------------
// NimBLE callback bridges
// ---------------------------------------------------------------------------

class SwitchbotKeypadBridge::ServerCallbacks : public NimBLEServerCallbacks {
 public:
  explicit ServerCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onConnect(NimBLEServer *server, NimBLEConnInfo &info) override {
    this->parent_->push_connect_();
  }

  void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override {
    this->parent_->push_disconnect_();
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::RxCharCallbacks : public NimBLECharacteristicCallbacks {
 public:
  explicit RxCharCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onWrite(NimBLECharacteristic *characteristic, NimBLEConnInfo &info) override {
    const std::string value = characteristic->getValue();
    if (value.empty())
      return;
    this->parent_->push_rx_(value);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::BatteryScanCallbacks : public NimBLEScanCallbacks {
 public:
  explicit BatteryScanCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onResult(const NimBLEAdvertisedDevice *adv) override {
    this->parent_->handle_battery_advert_(adv);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

// ---------------------------------------------------------------------------
// Thread-safe event queueing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::push_connect_() {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::CONNECT, ""});
}

void SwitchbotKeypadBridge::push_disconnect_() {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::DISCONNECT, ""});
}

void SwitchbotKeypadBridge::push_rx_(const std::string &frame) {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::RX, frame});
}

// ---------------------------------------------------------------------------
// Component lifecycle
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::setup() {
  // Load — or, on first boot, generate — the 16-byte AES-128 session key.
  // unpair() rotates it; it is never part of the YAML config.
  this->shared_key_pref_ =
      global_preferences->make_preference<std::array<uint8_t, 16>>(0x534B4559UL /* 'SKEY' */);
  if (!this->shared_key_pref_.load(&this->shared_key_)) {
    this->create_shared_key_();
    ESP_LOGI(TAG, "Generated a fresh shared key");
  }

  // Restore the paired keypad name (if any) and publish it to the sensor.
  this->keypad_name_pref_ = global_preferences->make_preference<char[KEYPAD_NAME_MAX]>(
      0x534B5042UL /* 'SKPB' */);
  char stored_name[KEYPAD_NAME_MAX] = {};
  bool have_keypad = false;
  if (this->keypad_name_pref_.load(&stored_name) && stored_name[0] != '\0') {
    stored_name[KEYPAD_NAME_MAX - 1] = '\0';
    have_keypad = true;
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state(stored_name);
    }
    ESP_LOGI(TAG, "Paired keypad: '%s'", stored_name);
  } else {
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state("Unpaired");
    }
  }
  this->keypad_paired_ = have_keypad;

  // Restore the keypad MAC + family used by the battery advert scan. Missing
  // for keypads paired before this field existed — the scan learns it then.
  this->keypad_info_pref_ =
      global_preferences->make_preference<KeypadInfo>(0x534B4D43UL /* 'SKMC' */);
  if (!this->keypad_info_pref_.load(&this->keypad_info_)) {
    this->keypad_info_ = KeypadInfo{};
  }
  this->battery_scan_callbacks_ = new BatteryScanCallbacks(this);
  this->next_battery_scan_at_ = millis() + BATTERY_SCAN_RETRY_MS;

  if (!this->prepare_keys_() || !this->prepare_ble_()) {
    this->mark_failed();
    return;
  }
  ESP_LOGI(TAG, "Ready. Advertising on %s",
           NimBLEDevice::getAddress().toString().c_str());

  this->pairing_ui_.set_shared_key(this->shared_key_);
  this->pairing_ui_.set_on_paired_callback(
      [this](const std::string &name, const std::string &mac,
             KeypadFamily family) {
        // Runs on the HTTP-server task — keep it minimal: stash the fields and
        // raise a flag. loop() (the main task) publishes the text sensor,
        // writes NVS and stops the server.
        this->pending_keypad_name_ = name;
        this->pending_keypad_mac_ = mac;
        this->pending_keypad_family_ = family;
        this->pending_pair_apply_.store(true, std::memory_order_release);
      });
  // Pairing mode: with no keypad paired yet, open the wizard right away
  // so the very first pairing needs no button press.
  if (!have_keypad) {
    if (this->pairing_ui_.start()) {
      ESP_LOGI(TAG, "No keypad paired — starting pairing mode");
    } else {
      ESP_LOGW(TAG, "Pairing UI failed to start; check port 80 is free");
    }
  }
}

void SwitchbotKeypadBridge::loop() {
  // Apply a pairing that completed on the HTTP-server task. The text-sensor
  // publish and the NVS write run here, on the main task.
  if (this->pending_pair_apply_.exchange(false, std::memory_order_acquire)) {
    const std::string &name = this->pending_keypad_name_;

    // Persist the name so it survives a reboot and can be re-published.
    char buf[KEYPAD_NAME_MAX] = {};
    name.copy(buf, sizeof(buf) - 1);
    const bool saved = this->keypad_name_pref_.save(&buf);

    // Persist the keypad's MAC + family for the battery advert scan.
    KeypadInfo info{};
    if (parse_mac_pretty(this->pending_keypad_mac_, info.mac)) {
      info.family = static_cast<uint8_t>(this->pending_keypad_family_);
      info.valid = 1;
    }
    this->keypad_info_ = info;
    this->keypad_info_pref_.save(&this->keypad_info_);
    global_preferences->sync();

    this->keypad_paired_ = true;
    this->last_battery_ = -1;
    // Pick the new keypad's battery up shortly, not a full interval away.
    this->next_battery_scan_at_ = millis() + 10000;

    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state(name);
    }
    ESP_LOGI(TAG, "Paired keypad: '%s' (nvs save %s)", name.c_str(),
             saved ? "ok" : "FAILED");

    // Pairing done — close the wizard server. Defer ~2 s so the wizard's
    // final status poll still gets its reply. set_timeout() is safe here:
    // loop() runs on the main task.
    this->set_timeout(2000, [this]() {
      this->pairing_ui_.stop();
      ESP_LOGI(TAG, "Pairing UI stopped");
    });
  }

  // Drain the RX queue. Swapping the vector out keeps the critical section
  // free of allocation and copying, so the NimBLE task never waits on it.
  std::vector<QueuedEvent> pending;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    pending.swap(this->rx_queue_);
  }

  for (const auto &ev : pending) {
    if (ev.type == QueuedEvent::CONNECT) {
      ESP_LOGI(TAG, "Keypad connected");
      this->session_.reset();
    } else if (ev.type == QueuedEvent::DISCONNECT) {
      ESP_LOGI(TAG, "Keypad disconnected, restarting advertising");
      this->session_.reset();
      NimBLEDevice::startAdvertising();
    } else if (ev.type == QueuedEvent::RX) {
      this->on_rx_frame_(ev.frame);
    }
  }

  if (this->battery_level_sensor_ != nullptr) {
    this->apply_pending_battery_();
    this->maybe_start_battery_scan_();
  }
}

void SwitchbotKeypadBridge::unpair() {
  ESP_LOGI(TAG, "Unpairing — rotating the shared key and re-opening the pairing wizard");

  // Rotate the key and swap it into the live crypto slot: the previously
  // paired keypad can no longer command the bridge, with no reboot needed.
  this->create_shared_key_();
  if (!this->import_aes_key_()) {
    ESP_LOGE(TAG, "Key rotation failed — unpair aborted");
    return;
  }

  // Stop an in-flight battery scan window: the wizard's own blocking scans
  // share the NimBLE scan singleton and must not race it.
  if (this->battery_scan_active_.exchange(false)) {
    NimBLEScan *scan = NimBLEDevice::getScan();
    if (scan->isScanning()) {
      scan->stop();
    }
    scan->clearResults();
  }

  // Forget the paired keypad name and its battery-scan identity.
  char empty[KEYPAD_NAME_MAX] = {};
  this->keypad_name_pref_.save(&empty);
  this->keypad_info_ = KeypadInfo{};
  this->keypad_info_pref_.save(&this->keypad_info_);
  global_preferences->sync();
  if (this->keypad_text_sensor_ != nullptr) {
    this->keypad_text_sensor_->publish_state("Unpaired");
  }
  this->keypad_paired_ = false;
  this->last_battery_ = -1;
  if (this->battery_level_sensor_ != nullptr) {
    this->battery_level_sensor_->publish_state(NAN);
  }

  // Invalidate any in-flight BLE session — it is keyed to the old secret —
  // and forget the learned token slot along with it.
  this->session_.reset();
  this->session_.forget_slot();

  // Re-enter pairing mode straight away with the rotated key.
  this->pairing_ui_.set_shared_key(this->shared_key_);
  if (this->pairing_ui_.start()) {
    ESP_LOGI(TAG, "Unpaired — re-entering pairing mode");
  } else {
    ESP_LOGW(TAG, "Pairing UI failed to start; check port 80 is free");
  }
}

void UnpairButton::press_action() {
  if (this->parent_->is_pairing_active()) {
    ESP_LOGW(TAG, "Pairing is already active, ignoring Unpair action");
    return;
  }
  this->parent_->unpair();
}

void LockButton::press_action() {
  ESP_LOGI(TAG, "LockButton pressed - setting lock state to LOCKED");
  
  if (!this->parent_) {
    ESP_LOGE(TAG, "LockButton: parent is null!");
    return;
  }
  
  this->parent_->set_lock_state(true);
  ESP_LOGI(TAG, "LockButton: lock state successfully set to LOCKED");
}

void SwitchbotKeypadBridge::dump_config() {
  ESP_LOGCONFIG(TAG, "SwitchBot Keypad Bridge:");
  ESP_LOGCONFIG(TAG, "  BLE address: %s", NimBLEDevice::getAddress().toString().c_str());
  ESP_LOGCONFIG(TAG, "  Pairing UI: port 80");
  if (this->battery_level_sensor_ != nullptr) {
    ESP_LOGCONFIG(TAG, "  Battery scan interval: %us",
                  static_cast<unsigned>(this->battery_scan_interval_ms_ / 1000));
  }
  if (this->is_failed()) {
    ESP_LOGE(TAG, "  Initialization failed - see previous errors");
  }
}

void SwitchbotKeypadBridge::create_shared_key_() {
  esp_fill_random(this->shared_key_.data(), this->shared_key_.size());
  this->shared_key_pref_.save(&this->shared_key_);
  global_preferences->sync();
}

bool SwitchbotKeypadBridge::import_aes_key_() {
  // Drop any previously imported handle so the slot can be re-keyed in
  // place — unpair() rotates the key without rebooting.
  if (this->aes_key_handle_ != PSA_KEY_ID_NULL) {
    psa_destroy_key(this->aes_key_handle_);
    this->aes_key_handle_ = PSA_KEY_ID_NULL;
  }

  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);
  psa_status_t status = psa_import_key(&attrs, this->shared_key_.data(), AES_KEY_SIZE,
                                       &this->aes_key_handle_);
  psa_reset_key_attributes(&attrs);

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }
  this->session_.set_aes_key(this->aes_key_handle_);
  return true;
}

bool SwitchbotKeypadBridge::prepare_keys_() {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "PSA Crypto init failed (%d)", static_cast<int>(status));
    return false;
  }
  return this->import_aes_key_();
}

bool SwitchbotKeypadBridge::prepare_ble_() {
  // Spoof a SwitchBot-OUI BLE address: keep the chip-unique tail, replace
  // the leading three bytes. The Vision keypad filters scan results on this
  // prefix and would otherwise ignore the bridge. Must run before NimBLE
  // init so the controller picks up the patched base MAC.
  uint8_t base[6];
  esp_err_t err = esp_efuse_mac_get_default(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_efuse_mac_get_default failed (err=0x%X)", err);
    return false;
  }
  std::memcpy(base, SPOOFED_OUI, sizeof(SPOOFED_OUI));
  err = esp_base_mac_addr_set(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_base_mac_addr_set failed (err=0x%X)", err);
    return false;
  }
  ESP_LOGD(TAG, "Base MAC set to %02X:%02X:%02X:%02X:%02X:%02X (SwitchBot OUI spoof)",
           base[0], base[1], base[2], base[3], base[4], base[5]);

  NimBLEDevice::init("WoLock");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  this->server_ = NimBLEDevice::createServer();
  this->server_->setCallbacks(new ServerCallbacks(this));

  NimBLEService *service = this->server_->createService(SERVICE_UUID);
  this->tx_characteristic_ = service->createCharacteristic(TX_CHAR_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic *rx = service->createCharacteristic(
      RX_CHAR_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCharCallbacks(this));

  NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
  advertising->addServiceUUID(service->getUUID());
  advertising->setManufacturerData(
      std::string(reinterpret_cast<const char *>(ADVERTISING_MFG_DATA), sizeof(ADVERTISING_MFG_DATA)));
  advertising->start();
  return true;
}

// ---------------------------------------------------------------------------
// RX path
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::on_rx_frame_(const std::string &frame) {
  switch (this->session_.process_frame(frame)) {
    case LockSession::Action::SEND_IV:
      this->notify_(this->session_.iv_response(), this->session_.iv_response_size());
      return;
    case LockSession::Action::COMMAND:
      this->handle_command_(this->session_.header(), this->session_.command());
      return;
    case LockSession::Action::NONE:
    default:
      return;  // dropped — the session logged why
  }
}

void SwitchbotKeypadBridge::handle_command_(const FrameHeader &header, const DecodedCommand &command) {
  switch (command.type) {
    case CommandType::LOCK:
      ESP_LOGI(TAG, "Lock");
      this->lock_state_ = LockState::LOCKED;
      this->publish_lock_();
      this->send_encrypted_response_(header, RESPONSE_LOCK, sizeof(RESPONSE_LOCK));
      return;

    case CommandType::UNLOCK:
      ESP_LOGI(TAG, "Unlock: method=%s (0x%02X) index=%d",
               unlock_method_name(command.method),
               static_cast<uint8_t>(command.method), command.credential_index);
      this->lock_state_ = LockState::UNLOCKED;
      this->publish_unlock_(command.method, command.credential_index);
      this->send_encrypted_response_(header, RESPONSE_UNLOCK, sizeof(RESPONSE_UNLOCK));
      return;

    case CommandType::STATE_POLL:
      ESP_LOGV(TAG, "State poll");
      this->handle_state_poll_(header);
      return;

    case CommandType::DOORBELL:
      ESP_LOGI(TAG, "Doorbell");
      this->publish_doorbell_();
      // No lock-state change; the keypad only needs the transport ACK.
      this->send_ack_(header);
      return;

    case CommandType::UNKNOWN:
    default:
      this->send_ack_(header);
      return;
  }
}

void SwitchbotKeypadBridge::handle_state_poll_(const FrameHeader &header) {
  uint8_t state_payload[1 + sizeof(STATE_PAYLOAD_TAIL)];
  state_payload[0] = static_cast<uint8_t>(this->lock_state_);
  std::memcpy(state_payload + 1, STATE_PAYLOAD_TAIL, sizeof(STATE_PAYLOAD_TAIL));
  this->send_encrypted_response_(header, state_payload, sizeof(state_payload));
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::send_ack_(const FrameHeader &header) {
  const uint8_t ack[LockSession::HEADER_LEN] = {0x01, header.key_id, header.seq_a, header.seq_b};
  this->notify_(ack, sizeof(ack));
}

void SwitchbotKeypadBridge::send_encrypted_response_(const FrameHeader &header,
                                                    const uint8_t *plaintext, size_t length) {
  uint8_t packet[LockSession::MAX_PACKET];
  const size_t n = this->session_.encrypt_response(header, plaintext, length, packet);
  if (n == 0) {
    return;  // error already logged
  }
  this->notify_(packet, n);
}

void SwitchbotKeypadBridge::notify_(const uint8_t *data, size_t length) {
  this->tx_characteristic_->setValue(data, length);
  this->tx_characteristic_->notify();
}

// ---------------------------------------------------------------------------
// Eventing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::publish_lock_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Lock");
  }
  this->on_lock_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_unlock_(UnlockMethod method, int index) {
  const char *method_str = unlock_method_name(method);
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Unlock");
  }
  this->on_unlock_callbacks_.call(std::string(method_str), index);
}

void SwitchbotKeypadBridge::publish_doorbell_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Doorbell");
  }
  this->on_doorbell_callbacks_.call();
}

// ---------------------------------------------------------------------------
// Keypad battery (advertisement scan)
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::maybe_start_battery_scan_() {
  const uint32_t now = millis();

  if (this->battery_scan_active_) {
    // NimBLE drops isScanning() when the window elapses or stop() ran.
    if (!NimBLEDevice::getScan()->isScanning()) {
      this->battery_scan_active_ = false;
      NimBLEDevice::getScan()->clearResults();
      this->next_battery_scan_at_ = now + this->battery_scan_interval_ms_;
    }
    return;
  }

  if (static_cast<int32_t>(now - this->next_battery_scan_at_) < 0) {
    return;
  }

  // The scan singleton is shared with the pairing flows (which run blocking
  // scans), and the keypad does not advertise while it holds a connection to
  // us — defer rather than fight either.
  if (!this->keypad_paired_ || this->pairing_ui_.is_running() ||
      (this->server_ != nullptr && this->server_->getConnectedCount() > 0) ||
      NimBLEDevice::getScan()->isScanning()) {
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
    return;
  }

  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(this->battery_scan_callbacks_, false);
  configure_switchbot_scan(scan);
  if (scan->start(BATTERY_SCAN_DURATION_MS, false, true)) {
    this->battery_scan_active_ = true;
    ESP_LOGD(TAG, "Battery scan window opened (%u ms)",
             static_cast<unsigned>(BATTERY_SCAN_DURATION_MS));
  } else {
    ESP_LOGW(TAG, "Battery scan failed to start");
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
  }
}

void SwitchbotKeypadBridge::handle_battery_advert_(const NimBLEAdvertisedDevice *adv) {
  // The callbacks stay registered on the shared scan singleton, so pairing
  // scans fire them too — only act inside our own scan window.
  if (!this->battery_scan_active_.load(std::memory_order_relaxed)) {
    return;
  }

  const std::array<uint8_t, 6> mac = addr_bytes(adv->getAddress());
  const std::vector<uint8_t> sd = switchbot_service_data(adv);

  KeypadFamily family;
  if (this->keypad_info_.valid != 0) {
    if (std::memcmp(mac.data(), this->keypad_info_.mac, mac.size()) != 0) return;
    family = static_cast<KeypadFamily>(this->keypad_info_.family);
  } else {
    // Keypad paired before the MAC was persisted: adopt the first advert
    // matching a known keypad signature (loop() persists it).
    const KeypadIdent ident = identify_keypad(sd.data(), sd.size());
    if (!ident.is_keypad) return;
    family = ident.family;
  }

  std::string mfr;
  if (adv->haveManufacturerData()) {
    mfr = adv->getManufacturerData();
  }
  const int battery = parse_keypad_battery(
      family, sd.data(), sd.size(),
      reinterpret_cast<const uint8_t *>(mfr.data()), mfr.size());
  if (battery < 0) {
    return;
  }

  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->battery_advert_value_ = battery;
  std::memcpy(this->battery_advert_mac_, mac.data(), mac.size());
  this->battery_advert_family_ = static_cast<uint8_t>(family);
  this->battery_advert_pending_ = true;
}

void SwitchbotKeypadBridge::apply_pending_battery_() {
  int value;
  uint8_t mac[6];
  uint8_t family;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    if (!this->battery_advert_pending_) return;
    this->battery_advert_pending_ = false;
    value = this->battery_advert_value_;
    std::memcpy(mac, this->battery_advert_mac_, sizeof(mac));
    family = this->battery_advert_family_;
  }

  if (this->keypad_info_.valid == 0) {
    std::memcpy(this->keypad_info_.mac, mac, sizeof(this->keypad_info_.mac));
    this->keypad_info_.family = family;
    this->keypad_info_.valid = 1;
    this->keypad_info_pref_.save(&this->keypad_info_);
    global_preferences->sync();
    ESP_LOGI(TAG, "Learned keypad MAC %02X:%02X:%02X:%02X:%02X:%02X from advertisement",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  }

  // Got what we came for — close the scan window early.
  if (this->battery_scan_active_ && NimBLEDevice::getScan()->isScanning()) {
    NimBLEDevice::getScan()->stop();
  }

  ESP_LOGD(TAG, "Keypad battery: %d%%", value);
  if (this->battery_level_sensor_ != nullptr && value != this->last_battery_) {
    this->last_battery_ = value;
    this->battery_level_sensor_->publish_state(static_cast<float>(value));
  }
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
