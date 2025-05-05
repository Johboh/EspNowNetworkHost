#ifndef __ESP_NOW_HOST_H__
#define __ESP_NOW_HOST_H__

#include <GCMEncryption.h>
#include <esp_idf_version.h>
#include <esp_log.h>
#include <esp_now.h>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>

/**
 * @brief ESP Now Network: Host
 *
 * This is the host engine for the EspNowNetwork and works together with nodes running the EspNowNode engines.
 * The host is intended to always be up and running to listen for messages from the nodes.
 * A common setup is that the host is also connecting to WiFi and forward all incoming messages to for example MQTT.
 *
 * The Host part of the EspNowNetwork supports the following:
 * - Setting up ESP-NOW: start().
 * - Listen for (and responds to) discovery requests from nodes (for nodes to disover the host).
 * - Listen for (and responds to) challenge requests from nodes (for encryption reply attacks protection).
 * - forwards all incoming application messages in the lambda callback.
 *
 * Check the main README.md file for the full EspNowNetwork overview.
 */
class EspNowHost {
public:
  struct MessageMetadata {
    // How many times the sender tried to send the message until it was received by the host.
    // useful to identify nodes with poor connection.
    uint8_t retries = 0;
    uint64_t mac_address; // MAC address of the sender node as an uint64_t
  };

  /**
   * @brief Callback when the host want to log something.
   *
   * This doesn't need to be implemented. But can be used to print debug information to serial
   * or post debug information to for example an MQTT topic.
   *
   * @param message the log message to log.
   * @param log_level the severity of the log.
   */
  typedef std::function<void(const std::string message, const esp_log_level_t log_level)> OnLog;

  typedef std::function<void(void)> OnNewMessage;

  /**
   * @brief Callback on valid application message received.
   *
   * @param metadata metadata for the message.
   * @param message the received decrypted, validated application message.
   */
  typedef std::function<void(MessageMetadata metadata, const uint8_t *message)> OnApplicationMessage;

  struct FirmwareUpdate {
    char wifi_ssid[32];     // WiFi SSID that node should connect to.
    char wifi_password[32]; // WiFi password that the node should connect to.
    char url[96];           // url where to find firmware binary. Note the max file path.
    char md5[32];           // MD5 hash of firmware. Does not include trailing \0
  };

  /**
   * @brief Callback that if returning a [FirmwareUpdate], will tell host to upgrade its firmware given the metadata in
   * [FirmwareUpdate].
   *
   * @param mac_address the MAC address of the node.
   * @param firmware_version firmware version as reported by the node.
   * return std::nullopt if there is no firmware update available for the given mac_address
   */
  typedef std::function<std::optional<FirmwareUpdate>(uint64_t mac_address, uint32_t firmware_version)>
      FirmwareUpdateAvailable;

  enum class WiFiInterface {
    AP,  // Use the Access Point interface for ESP-NOW.
    STA, // Use the Station/Client interface for ESP-NOW.
  };

  struct Configuration {
    /**
     * @brief what network interface to use to send ESP-NOW messages on. You need to setup this interface beforehand
     * when setting up your WiFi.
     */
    WiFiInterface wifi_interface = WiFiInterface::STA;
    /**
     * @brief If true, will create a task that will print if messages sent to nodes was delivered sucessful or not.
     * Useful for debugging.
     */
    bool with_delivered_task = true;
  };

public:
  /**
   * @brief Construct a new EspNowHost
   *
   * @param crypt the GCMEncryption to use for encrypting/decrypting messages.
   * @param configuration the configuration to use.
   * @param on_new_message callback on any new message received, regardless of type, validation, decrypted correctly
   * etc. Intended for turning on led or similar to indicate new package. Please note that this function will be
   * called on every challenge request sent by the node, so this function must return fast and not perform any heavy
   * computation or network.
   * @param on_application_message callback when there is a verified, decrypted application message received. Please
   * note that this function will be called on every challenge request sent by the node, so this function must
   * return fast and not perform any heavy computation or network.
   * @param firwmare_update callback to check if a firmware update is available. Please note that this function will
   * be called on every challenge request sent by the node, so this function must return fast and not perform any
   * heavy computation or network. This function should preferably just do a lookup in a lookup table to check if a
   * given node and its firmware version have new firmware.
   * @param on_log callback when the host want to log something. Please note that this function will be
   * called on every challenge request sent by the node, so this function must return fast and not perform any heavy
   * computation or network.
   */
  EspNowHost(GCMEncryption &crypt, Configuration configuration, OnNewMessage on_new_message,
             OnApplicationMessage on_application_message, FirmwareUpdateAvailable firwmare_update = {},
             OnLog on_log = {});

public:
  /**
   * @brief Setup the ESP-NOW stack.
   */
  bool start();
  bool setup() { return start(); }

  /**
   * If called with a payload, the node will receive this buffer in the next challenge, unless there is a firmware
   * update. This can be useful to pass any application data to the node, like configurations.
   * Any payload set here will be kept and sent on next challenge request, and once sent sucessfully, it will be
   * cleared. The payload will be copied into the outgoing payload queue, so no need to hold onto the buffer.
   * Any call to this will override any previous payload if payload has not been delivered yet.
   * pendingOutgoingPayload() can be used to check if payload has been sent.
   * Any firmware update will take precedence over payloads.
   *
   * Call with null buffer and/or 0 size to clear any pending payload.
   *
   * @param mac_address the mac address of the node to send the payload to.
   * @param buffer pointer to the buffer to send, of size.
   * @param size the size in bytes, maxium 200 bytes, of payload.
   */
  void setPayload(uint64_t mac_address, uint8_t *buffer, uint8_t size);

  /**
   * Return true if there is a pending outgoing payload, set by setPayload(), that has not been delivered yet.
   */
  bool pendingOutgoingPayload(uint64_t mac_address);

  /**
   * @brief Allow skipping challenge requests for specific nodes.
   *
   * If the host allows it, challenge requests can be skipped per mac address of node.
   *
   * Normally challenge requests are used to prevent replay attacks, when the node is requesting a unique challenge from
   * the host to use in the subsequent message. This challenge is randomized by the host. Upon responding to the
   * challenge request, the host also have the option to indicate that there is a new firmware as well as send any
   * additional payload/configuration. By skipping the challenge request, these two options are not possible. During the
   * challenge request, there is a detection mechanism on the node to detect WiFi channel change as well as change of
   * host, if we prevoulsy had a valid channel and host. If challenge request is disabled, this check will also not
   * happen.
   *
   * For the node, challenge requests involves sending and receiving one additional package. Disabling challenge
   * request will reduce latency and save power consumption, but with a cost in terms of reduced security, error
   * detection and firwmare/payload support.
   *
   * If a challenge request is recived, the host will always anwer it even if the host is allowed to not require them.
   *
   * @param mac_addresses a set of mac addresses to allow skipping challenge requests for. Empty list to require
   * challenge requests for all nodes, which is the default.
   */
  void allowToSkipChallengeVerification(std::set<uint64_t> mac_addresses);

private:
  static void esp_now_on_data_sent(const uint8_t *mac_addr, esp_now_send_status_t status);
  static void esp_now_on_data_callback_legacy(const uint8_t *mac_addr, const uint8_t *data, int data_len);
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
  static void esp_now_on_data_callback(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int data_len);
#endif

  static void newMessageTask(void *pvParameters);
  static void messageDeliveredTask(void *pvParameters);

  void handleQueuedMessage(uint8_t *mac_addr, uint8_t *data);
  void handleDiscoveryRequest(uint8_t *mac_addr, uint32_t discovery_challenge);
  void handleChallengeRequest(uint8_t *mac_addr, uint32_t challenge_challenge, uint32_t firmware_version);

  void sendMessageToTemporaryPeer(uint8_t *mac_addr, void *message, size_t length);

  static uint64_t macToMac(uint8_t *mac_addr);

  void log(const std::string message, const esp_log_level_t log_level);
  void log(const std::string message, const esp_err_t esp_err);

  static std::string toHex(uint64_t i);

private:
  GCMEncryption &_crypt;
  Configuration _configuration;
  // Map from MAC address to challenge.
  std::map<uint64_t, uint32_t> _challenges;

  struct Payload {
    uint8_t *buffer;
    uint8_t size;
  };

  // Map of payloads to send.
  std::map<uint64_t, Payload> _payloads;

  OnLog _on_log;
  OnNewMessage _on_new_message;
  FirmwareUpdateAvailable _firwmare_update;
  OnApplicationMessage _on_application_message;
  std::set<uint64_t> _allow_to_skip_challenge_verification;
};

#endif // __ESP_NOW_HOST_H__