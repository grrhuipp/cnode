#include "acppnode/transport/internet/stream_settings.hpp"
#include "tls_context_cache_key.hpp"

#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::transport::internet::MakeRealityClientContextCacheKey;
    using acpp::transport::internet::MakeRealityServerContextCacheKey;
    using acpp::transport::internet::MakeTlsContextCacheKey;

    acpp::TlsConfig joined_alpn;
    joined_alpn.alpn = {"h2|http/1.1"};
    acpp::TlsConfig split_alpn;
    split_alpn.alpn = {"h2", "http/1.1"};
    if (!Require(MakeTlsContextCacheKey("client", joined_alpn) !=
                     MakeTlsContextCacheKey("client", split_alpn),
                 "different ALPN sequences must not share a cache key")) {
        return 1;
    }

    acpp::TlsConfig joined_paths;
    joined_paths.cert_file = "a|b";
    joined_paths.key_file = "c";
    acpp::TlsConfig split_paths;
    split_paths.cert_file = "a";
    split_paths.key_file = "b|c";
    if (!Require(MakeTlsContextCacheKey("server", joined_paths) !=
                     MakeTlsContextCacheKey("server", split_paths),
                 "different certificate paths must not share a cache key")) {
        return 2;
    }

    acpp::RealityConfig joined_server_names;
    joined_server_names.server_names = {"a|b"};
    acpp::RealityConfig split_server_names;
    split_server_names.server_names = {"a", "b"};
    acpp::TlsConfig tls;
    if (!Require(MakeRealityServerContextCacheKey(joined_server_names, tls) !=
                     MakeRealityServerContextCacheKey(split_server_names, tls),
                 "different REALITY server-name lists must not share a cache key")) {
        return 3;
    }

    acpp::RealityConfig joined_short_ids;
    joined_short_ids.short_ids = {"a,b"};
    acpp::RealityConfig split_short_ids;
    split_short_ids.short_ids = {"a", "b"};
    if (!Require(MakeRealityServerContextCacheKey(joined_short_ids, tls) !=
                     MakeRealityServerContextCacheKey(split_short_ids, tls),
                 "different REALITY short-ID lists must not share a cache key")) {
        return 4;
    }

    acpp::RealityConfig joined_client;
    joined_client.public_key = "a|b";
    joined_client.server_name = "c";
    acpp::RealityConfig split_client;
    split_client.public_key = "a";
    split_client.server_name = "b|c";
    if (!Require(MakeRealityClientContextCacheKey(joined_client, tls) !=
                     MakeRealityClientContextCacheKey(split_client, tls),
                 "different REALITY client fields must not share a cache key")) {
        return 5;
    }
    return 0;
}
