// Deliberately include this first and do not include the transport implementation
// or TLS configuration. A PImpl facade must be usable without either definition.
#include "acppnode/transport/internet/tls_stream.hpp"

#include <concepts>
#include <memory>
#include <type_traits>
#include <utility>

namespace {

template <typename T>
concept Complete = requires { sizeof(T); };

static_assert(!Complete<acpp::TcpStream>);
static_assert(!Complete<acpp::TlsConfig>);
static_assert(!Complete<SSL> && !Complete<SSL_CTX>);
static_assert(std::derived_from<acpp::TlsStream, acpp::AsyncStream>);
static_assert(std::is_constructible_v<acpp::TlsStream,
    std::unique_ptr<acpp::TcpStream>, SSL_CTX*, bool>);
static_assert(std::same_as<
    decltype(std::declval<acpp::SslContext&>().Native()), SSL_CTX*>);
static_assert(std::same_as<
    decltype(acpp::SslContext::CreateClient(std::declval<const acpp::TlsConfig&>())),
    std::unique_ptr<acpp::SslContext>>);
static_assert(std::same_as<
    decltype(std::declval<acpp::TlsStream&>().Handshake()), acpp::net::awaitable<bool>>);

}  // namespace

int main() {}
