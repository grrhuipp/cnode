#include "anytls_padding.hpp"

#include <poll.h>

namespace cnode::e2e::padding {
namespace {
struct BoundsCase { const char* name; size_t size; bool unicode; bool array; };
std::string SchemeBytes(size_t size, bool unicode) {
    std::string raw = "stop=8\n0=30-30\n1=64-65\n#";
    const std::string_view unit = unicode ? "\xe7\x95\x8c" : "a";
    while (raw.size() + unit.size() <= size) raw += unit;
    raw.append(size - raw.size(), 'x');
    return raw;
}
class AnyTlsPaddingBounds : public testing::TestWithParam<BoundsCase> {};
TEST_P(AnyTlsPaddingBounds, ColdAdmissionUsesUtf8BytesAndExactUpdateFrameCapacity) {
    const auto& test = GetParam();
    const auto raw = SchemeBytes(test.size, test.unicode);
    ASSERT_EQ(raw.size(), test.size);
    TempDir root;
    auto destination = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Configure(root.Path(), AnyInbound(port, PolicySetting(raw, test.array)),
              {{"protocol", "freedom"}, {"settings", Json::object()}});
    reservation.Close();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    Until([&] { return !child.Running() || ReadFile(child.LogPath()).find("server started") != std::string::npos; }, 8s);
    if (test.size > 65535) {
        ASSERT_FALSE(child.Running());
        EXPECT_NE(child.Wait(), 0);
        std::string diagnostics = ReadFile(child.LogPath());
        EXPECT_EQ(diagnostics.find("server started"), std::string::npos);
        const auto logs = root.Path() / "logs";
        if (std::filesystem::exists(logs)) {
            for (const auto& entry : std::filesystem::directory_iterator(logs)) {
                if (entry.is_regular_file() && entry.path().filename().string().starts_with("error_"))
                    diagnostics += ReadFile(entry.path());
            }
        }
        EXPECT_TRUE(diagnostics.find("paddingScheme exceeds 65535 bytes") != std::string::npos ||
                    diagnostics.find("padding scheme exceeds 65535 bytes") != std::string::npos) << diagnostics;
        pollfd pending{destination.Fd(), POLLIN, 0};
        EXPECT_EQ(::poll(&pending, 1, 0), 0) << "rejected configuration reached destination";
        return;
    }
    ASSERT_TRUE(child.Running());
    std::string request;
    PeerThread target([&] {
        auto socket = destination.Accept();
        request = socket.ReadExact(Request.size());
        socket.Write(Banner);
    });
    TlsContext tls(false);
    TlsSocket socket(ConnectEventually(port), tls, false);
    AnyTlsAuthenticate(socket, "secret");
    socket.Write(AnyTlsFrame(4, 0, "v=2\npadding-md5=outdated") + AnyTlsFrame(1, 1) +
                 AnyTlsFrame(2, 1, SocksAddress(destination.Port()) + std::string(Request)));
    auto updates = ReceiveInbound(socket, 1);
    DrainBarrier(socket, updates);
    EXPECT_EQ(updates, std::vector<std::string>{raw});
    target.Join();
    EXPECT_EQ(request, Request);
    EXPECT_TRUE(child.Running());
}
INSTANTIATE_TEST_SUITE_P(ByteCapacity, AnyTlsPaddingBounds, testing::Values(
    BoundsCase{"SmallAsciiText", 31, false, false},
    BoundsCase{"BelowMaximumAsciiText", 65534, false, false},
    BoundsCase{"MaximumAsciiText", 65535, false, false},
    BoundsCase{"MaximumUtf8Text", 65535, true, false},
    BoundsCase{"MaximumUtf8Array", 65535, true, true},
    BoundsCase{"OverflowAsciiText", 65536, false, false},
    BoundsCase{"OverflowUtf8Text", 65536, true, false},
    BoundsCase{"OverflowUtf8Array", 65536, true, true}
), [](const testing::TestParamInfo<BoundsCase>& info) { return info.param.name; });
} // namespace
} // namespace cnode::e2e::padding
