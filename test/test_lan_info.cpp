#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <tether/bluetooth/lan_info.hpp>
#include <vector>

using tether::bluetooth::encode_lan_info;
using tether::bluetooth::LAN_INFO_MAX_BYTES;

TEST(LanInfoTest, EncodesContract) {
    const auto doc = nlohmann::json::parse(encode_lan_info("btw", 5134, "ab12", {"192.168.1.28/24", "fd12::5/64"}));
    EXPECT_EQ(doc["v"], 1);
    EXPECT_EQ(doc["name"], "btw");
    EXPECT_EQ(doc["port"], 5134);
    EXPECT_EQ(doc["fp"], "ab12");
    EXPECT_EQ(doc["addrs"], nlohmann::json::array({"192.168.1.28/24", "fd12::5/64"}));
}

TEST(LanInfoTest, DropsTailAddressesToFit) {
    std::vector<std::string> addrs;
    for (int i = 0; i < 60; ++i)
        addrs.push_back("10.0.0." + std::to_string(i) + "/24");
    const std::string out = encode_lan_info("host", 5134, std::string(64, 'f'), addrs);
    EXPECT_LE(out.size(), LAN_INFO_MAX_BYTES);

    const auto kept = nlohmann::json::parse(out)["addrs"];
    ASSERT_FALSE(kept.empty());
    ASSERT_LT(kept.size(), addrs.size());
    EXPECT_EQ(kept[0], addrs[0]);
    // Only whole entries are dropped, and only from the tail.
    for (size_t i = 0; i < kept.size(); ++i)
        EXPECT_EQ(kept[i], addrs[i]);
}

TEST(LanInfoTest, HostAddressesSkipLoopbackAndLinkLocal) {
    bool seen_v6 = false;
    for (const auto& addr : tether::bluetooth::lan_addresses()) {
        ASSERT_NE(addr.find('/'), std::string::npos) << addr;
        EXPECT_NE(addr.rfind("127.", 0), 0u) << addr;
        EXPECT_NE(addr.rfind("::1/", 0), 0u) << addr;
        EXPECT_NE(addr.rfind("fe80:", 0), 0u) << addr;
        const bool v6 = addr.find(':') != std::string::npos;
        EXPECT_FALSE(seen_v6 && !v6) << "IPv4 after IPv6: " << addr;
        seen_v6 = seen_v6 || v6;
    }
}

TEST(ClipboardBlePayload, ShortTextIsUntouched) {
    bool truncated = true;
    EXPECT_EQ(tether::bluetooth::clipboard_ble_payload("hello", truncated), "hello");
    EXPECT_FALSE(truncated);
    EXPECT_EQ(tether::bluetooth::clipboard_ble_payload("", truncated), "");
    EXPECT_FALSE(truncated);
}

TEST(ClipboardBlePayload, ExactlyTheLimitIsNotTruncated) {
    bool truncated = true;
    const std::string text(tether::bluetooth::CLIPBOARD_MAX_BYTES, 'a');
    EXPECT_EQ(tether::bluetooth::clipboard_ble_payload(text, truncated), text);
    EXPECT_FALSE(truncated);
}

TEST(ClipboardBlePayload, LongTextIsCutAtTheLimit) {
    bool truncated = false;
    const std::string text(tether::bluetooth::CLIPBOARD_MAX_BYTES + 100, 'a');
    const std::string out = tether::bluetooth::clipboard_ble_payload(text, truncated);
    EXPECT_TRUE(truncated);
    EXPECT_EQ(out.size(), tether::bluetooth::CLIPBOARD_MAX_BYTES);
}

TEST(ClipboardBlePayload, NeverSplitsAMultiByteCharacter) {
    // "é" is 2 bytes, "✓" 3, "👋" 4: a cut at every offset must still be valid UTF-8
    const std::string text = "aé✓👋"
                             "aé✓👋"
                             "aé✓👋";
    for (size_t limit = 0; limit < text.size(); ++limit) {
        bool truncated = false;
        const std::string out = tether::bluetooth::clipboard_ble_payload(text, truncated, limit);
        EXPECT_TRUE(truncated) << limit;
        EXPECT_LE(out.size(), limit) << limit;
        EXPECT_EQ(text.compare(0, out.size(), out), 0) << limit; // a prefix
        // the next byte starts a character, so nothing was cut mid-sequence
        EXPECT_NE(static_cast<unsigned char>(text[out.size()]) & 0xC0, 0x80) << limit;
    }
}

TEST(ClipboardAnnounce, EncodesSequenceSizeAndTruncation) {
    const auto doc = nlohmann::json::parse(tether::bluetooth::encode_clipboard_announce(7, 42, true));
    EXPECT_EQ(doc["v"], 1);
    EXPECT_EQ(doc["seq"], 7);
    EXPECT_EQ(doc["size"], 42);
    EXPECT_TRUE(doc["trunc"].get<bool>());
    EXPECT_LE(tether::bluetooth::encode_clipboard_announce(UINT64_MAX, 512, false).size(), 64u); // fits any MTU read
}
