#include "acppnode/transport/internet/tls_config.hpp"

#include <openssl/mem.h>

#include <cstdio>
#include <format>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace acpp {

namespace {

// Real chains and CA bundles are far smaller; the bound keeps a mistyped path
// to a device or an unrelated large file from stalling configuration load.
constexpr std::size_t kMaxTlsPemFileBytes = 1024 * 1024;

// The private key passes through here, so the file is read unbuffered into one
// allocation sized up front: no stdio/stream buffer and no growth copy keeps
// key bytes outside the returned string, and every error path wipes it.
std::string ReadTlsPemFile(const std::string& path, std::string_view kind) {
    const auto fail = [&](std::string_view reason) {
        return std::invalid_argument(
            std::format("cannot read TLS {} file '{}': {}", kind, path, reason));
    };
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> file(
        std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!file) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    if (std::setvbuf(file.get(), nullptr, _IONBF, 0) != 0 ||
        std::fseek(file.get(), 0, SEEK_END) != 0) {
        throw fail("read error");
    }
    const long size = std::ftell(file.get());
    if (size < 0 || std::fseek(file.get(), 0, SEEK_SET) != 0) throw fail("read error");
    if (size == 0) throw fail("empty");
    if (static_cast<unsigned long>(size) > kMaxTlsPemFileBytes) throw fail("larger than 1 MiB");

    std::string contents(static_cast<std::size_t>(size), '\0');
    const std::size_t read = std::fread(contents.data(), 1, contents.size(), file.get());
    // One byte more than announced means the file changed while being read.
    char probe = 0;
    const bool complete = read == contents.size() &&
        std::fread(&probe, 1, 1, file.get()) == 0 && !std::ferror(file.get());
    OPENSSL_cleanse(&probe, sizeof(probe));
    if (!complete) {
        OPENSSL_cleanse(contents.data(), contents.size());
        throw fail(std::ferror(file.get()) ? "read error" : "changed while reading");
    }
    return contents;
}

}  // namespace

TlsPemMaterial::~TlsPemMaterial() {
    OPENSSL_cleanse(private_key.data(), private_key.size());
}

void LoadTlsPemMaterial(TlsConfig& config) {
    if (config.cert_file.empty() && config.key_file.empty() &&
        config.ca_file.empty()) {
        config.pem.reset();
        return;
    }
    auto material = std::make_shared<TlsPemMaterial>();
    if (!config.cert_file.empty()) {
        material->certificate_chain =
            ReadTlsPemFile(config.cert_file, "certificate");
    }
    if (!config.key_file.empty()) {
        material->private_key = ReadTlsPemFile(config.key_file, "private key");
    }
    if (!config.ca_file.empty()) {
        material->trusted_ca = ReadTlsPemFile(config.ca_file, "CA");
    }
    config.pem = std::move(material);
}

}  // namespace acpp
