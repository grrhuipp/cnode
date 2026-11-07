#include "tls_wire.hpp"
#include <openssl/x509.h>

namespace cnode::e2e {
namespace {
using namespace tls;
TEST(TlsAutosign, LongConfiguredSanAndArbitrarySniUseOneCertificate) {
    TempDir root;
    auto reservation = Socket::Listen();
    auto port = reservation.Port();
    const std::string identity = std::string(63, 'a') + "." + std::string(63, 'b') + ".example.com";
    Config(root.Path(), Json::array({Inbound(port, {{"network", "tcp"}, {"security", "tls"},
        {"tlsSettings", {{"serverName", identity}}}})}), Json::array({Direct()}));
    reservation.Close();
    auto child = Start(root.Path());
    const std::string payload = "reality-end-to-end-verification-payload";
    std::unique_ptr<X509, decltype(&X509_free)> certificate(nullptr, X509_free);
    unsigned fragmented = 0;
    auto probe = [&](std::string_view name, TlsContext& context) {
        auto target = Socket::Listen();
        PeerThread backend([&] {
            auto socket = target.Accept();
            auto bytes = socket.ReadExact(payload.size());
            Require(bytes == payload, "autosign target payload");
            socket.Write(bytes);
        });
        FragmentingProxy proxy(port);
        WireTls client(Socket::Connect(proxy.Port()), context, false, name);
        std::unique_ptr<X509, decltype(&X509_free)> current(SSL_get_peer_certificate(client.Get()), X509_free);
        Require(current != nullptr, "server certificate absent");
        if (!certificate) certificate = std::move(current);
        else EXPECT_EQ(X509_cmp(certificate.get(), current.get()), 0);
        client.Write(VlessRequest(target.Port(), payload));
        EXPECT_EQ(client.ReadExact(2 + payload.size()), std::string(2, '\0') + payload);
        client.Raw().Close();
        backend.Join();
        proxy.Join();
        EXPECT_TRUE(proxy.fragmented.load());
        fragmented += proxy.fragmented.load();
    };
    TlsContext insecure(false);
    probe(identity, insecure);
    TlsContext trusted(false);
    Require(X509_STORE_add_cert(SSL_CTX_get_cert_store(trusted.Get()), certificate.get()) == 1, "trust generated certificate");
    SSL_CTX_set_verify(trusted.Get(), SSL_VERIFY_PEER, nullptr);
    probe(identity, trusted);
    for (unsigned i = 0; i < 16; ++i) probe("arbitrary-" + std::to_string(i) + ".invalid", insecure);
    FragmentingProxy rejected_proxy(port);
    EXPECT_THROW(WireTls(Socket::Connect(rejected_proxy.Port()), trusted, false, "not-configured.invalid"), std::runtime_error);
    rejected_proxy.Join();
    EXPECT_TRUE(rejected_proxy.fragmented.load());
    fragmented += rejected_proxy.fragmented.load();
    EXPECT_EQ(fragmented, 19u);
    EXPECT_TRUE(child->Running());
}
} // namespace
} // namespace cnode::e2e
