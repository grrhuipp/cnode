#include "transport/internet/tls_config.hpp"

#include <openssl/mem.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <format>
#include <stdexcept>
#include <string_view>


namespace {

// Real chains and CA bundles are far smaller; the bound keeps a mistyped path
// to a device or an unrelated large file from stalling configuration load.
constexpr std::size_t kMaxTlsPemFileBytes = 1024 * 1024;

struct FileDescriptor {
    int fd = -1;
    FileDescriptor() = default;
    explicit FileDescriptor(int value) noexcept : fd(value) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    ~FileDescriptor() {
        if (fd >= 0) ::close(fd);
    }
};

// The private key passes through here, so the file is read unbuffered into one
// allocation sized up front: no stdio/stream buffer and no growth copy keeps
// key bytes outside the returned string, and every error path wipes it.
std::string ReadTlsPemFile(const std::string& path, std::string_view kind) {
    const auto fail = [&](std::string_view reason) {
        return std::invalid_argument(
            std::format("cannot read TLS {} file '{}': {}", kind, path, reason));
    };
    if (path.find('\0') != std::string::npos) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    FileDescriptor file(::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (file.fd < 0) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    struct stat st{};
    if (::fstat(file.fd, &st) != 0) throw fail("read error");
    if (!S_ISREG(st.st_mode)) throw fail("not a regular file");
    if (st.st_size < 0) throw fail("read error");
    if (st.st_size == 0) throw fail("empty");
    if (static_cast<unsigned long long>(st.st_size) > kMaxTlsPemFileBytes) {
        throw fail("larger than 1 MiB");
    }

    std::string contents(static_cast<std::size_t>(st.st_size), '\0');
    std::size_t offset = 0;
    bool read_error = false;
    while (offset < contents.size()) {
        const ssize_t count = ::read(
            file.fd, contents.data() + offset, contents.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            read_error = true;
            break;
        }
        if (count == 0) break;
        offset += static_cast<std::size_t>(count);
    }
    // One byte more than announced means the file changed while being read.
    char probe = 0;
    ssize_t extra = 0;
    if (!read_error && offset == contents.size()) {
        do {
            extra = ::read(file.fd, &probe, 1);
        } while (extra < 0 && errno == EINTR);
        if (extra < 0) read_error = true;
    }
    OPENSSL_cleanse(&probe, sizeof(probe));
    if (read_error || offset != contents.size() || extra != 0) {
        OPENSSL_cleanse(contents.data(), contents.size());
        throw fail(read_error ? "read error" : "changed while reading");
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

