#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tether::bluetooth {

    class BluezMonitor;

    inline constexpr const char* UUID_TETHER_LAN_SERVICE = "ba7a69f7-bf0f-4c09-8c73-cf4ee9afb5b5";
    inline constexpr const char* UUID_TETHER_LAN_INFO = "ba7a69f7-bf0f-4c09-8c73-cf4ee9afb5b6";

    // Clipboard push for a phone that is bonded but has no open TCP session (iOS closes it when the app leaves the
    // foreground). Both characteristics sit in the LAN service and are readable only over an encrypted link.
    //   announce: notifies on every change, value `{"v":1,"seq":N,"size":S,"trunc":false}`
    //   text:     the clipboard as UTF-8, at most CLIPBOARD_MAX_BYTES, cut on a character boundary
    // A phone subscribes to `announce`; when it fires, it reads `text` (a long read: iOS does the offsets itself).
    inline constexpr const char* UUID_TETHER_CLIPBOARD_ANNOUNCE = "ba7a69f7-bf0f-4c09-8c73-cf4ee9afb5b7";
    inline constexpr const char* UUID_TETHER_CLIPBOARD_TEXT = "ba7a69f7-bf0f-4c09-8c73-cf4ee9afb5b8";

    // ATT caps an attribute value at 512 bytes.
    inline constexpr size_t LAN_INFO_MAX_BYTES = 512;
    inline constexpr size_t CLIPBOARD_MAX_BYTES = 512;

    // `text` cut to at most `max_bytes` without splitting a UTF-8 sequence; `truncated` reports whether it was cut.
    std::string clipboard_ble_payload(const std::string& text, bool& truncated, size_t max_bytes = CLIPBOARD_MAX_BYTES);

    // The announce characteristic's value for clipboard change number `seq` carrying `size` bytes.
    std::string encode_clipboard_announce(uint64_t seq, size_t size, bool truncated);

    // This host's addresses as "ip/prefix": interfaces that are up, without loopback or
    // IPv6 link-local, IPv4 first.
    std::vector<std::string> lan_addresses();

    // The characteristic value: compact JSON, addresses dropped from the tail until it fits.
    std::string encode_lan_info(const std::string& name,
                                uint16_t port,
                                const std::string& fingerprint,
                                std::vector<std::string> addresses);

    struct LanInfoState;

    // GATT service that tells a bonded phone where tetherd listens, for networks that block
    // mDNS. Lives on the monitor's thread; re-registers whenever bluetoothd comes back.
    class LanInfoService {
    public:
        LanInfoService(BluezMonitor& monitor, std::string name, uint16_t port, std::string fingerprint);
        ~LanInfoService();

        LanInfoService(const LanInfoService&) = delete;
        LanInfoService& operator=(const LanInfoService&) = delete;

        // Moves the registration to this adapter; empty withdraws it. Cheap when unchanged.
        void set_adapter(const std::string& adapter_path);

        // Makes `text` the clipboard offered to bonded phones and notifies any that subscribed. Any thread.
        void publish_clipboard(const std::string& text);

    private:
        BluezMonitor& monitor_;
        std::string adapter_;
        std::unique_ptr<LanInfoState> state_;
    };

    // The running service, if any, so code without a handle on it (the clipboard callback) can publish.
    void publish_clipboard_to_phones(const std::string& text);

} // namespace tether::bluetooth
