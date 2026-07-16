#include "acppnode/infra/access_log_reporter.hpp"

#include "access_log_encoding.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/co_spawn.hpp>
#include <asio/connect.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/redirect_error.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <concurrentqueue.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <format>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <sstream>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace acpp::accesslog {

namespace {

using namespace std::chrono_literals;
namespace ssl = net::ssl;

constexpr std::string_view kBearerToken =
    "51aba8b656f39b65d249ae6b2145fe07c1103dc64037b55d4c9d2b174d03ecb3";
constexpr size_t kQueueCapacity = 65536;
constexpr size_t kMaxBatchEvents = 1000;
constexpr size_t kMaxBatchProtobufBytes = 1024 * 1024;
constexpr uint64_t kMaxSpoolBytes = 5ULL * 1024 * 1024 * 1024;
constexpr size_t kMaxSpoolFileBytes = 8 * 1024 * 1024;
constexpr auto kFlushInterval = 250ms;
constexpr auto kConnectTimeout = 3s;
constexpr auto kRequestTimeout = 10s;
constexpr auto kInitialRetry = 500ms;
constexpr auto kMaxRetry = 60'000ms;

std::string LowerCopy(std::string_view value) {
    std::string out(value);
    std::ranges::transform(out, out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return out;
}

std::string TrimCopy(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

bool IsHexId(std::string_view value) noexcept {
    if (value.size() != 32) {
        return false;
    }
    return std::ranges::all_of(value, [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

detail::Id128 MakeBootId() noexcept {
    detail::Id128 id{};
    if (RAND_bytes(id.data(), static_cast<int>(id.size())) == 1) {
        return id;
    }

    uint64_t seed = static_cast<uint64_t>(NowMicros());
    for (size_t i = 0; i < id.size(); ++i) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        id[i] = static_cast<uint8_t>(seed >> ((i % 8) * 8));
    }
    return id;
}

std::string ResolveServerId() {
    try {
        std::string value = net::ip::host_name();
        if (!value.empty()) {
            return value;
        }
    } catch (...) {
    }
    return "cnode-unknown";
}

bool DurableWrite(const std::filesystem::path& path,
                  std::span<const uint8_t> payload) {
#ifdef _WIN32
    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"wb") != 0) {
        return false;
    }
#else
    FILE* file = std::fopen(path.string().c_str(), "wb");
    if (!file) {
        return false;
    }
#endif
    const size_t written = payload.empty()
        ? 0
        : std::fwrite(payload.data(), 1, payload.size(), file);
    bool ok = written == payload.size() && std::fflush(file) == 0;
    if (ok) {
#ifdef _WIN32
        ok = _commit(_fileno(file)) == 0;
#else
        ok = ::fsync(fileno(file)) == 0;
#endif
    }
    if (std::fclose(file) != 0) {
        ok = false;
    }
    return ok;
}

void SyncDirectory(const std::filesystem::path& path) noexcept {
#ifndef _WIN32
    const int fd = ::open(path.string().c_str(), O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
        (void)::fsync(fd);
        (void)::close(fd);
    }
#else
    (void)path;
#endif
}

#ifdef _WIN32
void LoadWindowsCaCertificates(ssl::context& ctx) {
    HCERTSTORE cert_store = CertOpenSystemStoreA(0, "ROOT");
    if (!cert_store) {
        return;
    }
    X509_STORE* store = SSL_CTX_get_cert_store(ctx.native_handle());
    for (PCCERT_CONTEXT cert = CertEnumCertificatesInStore(cert_store, nullptr);
         cert != nullptr;
         cert = CertEnumCertificatesInStore(cert_store, cert)) {
        const unsigned char* der = cert->pbCertEncoded;
        X509* x509 = d2i_X509(
            nullptr, &der, static_cast<long>(cert->cbCertEncoded));
        if (x509) {
            (void)X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }
    CertCloseStore(cert_store, 0);
}
#endif

struct HttpResponse {
    int status = 0;
    bool connection_close = false;
    std::optional<size_t> content_length;
    bool chunked = false;
    std::string body;
};

struct SendResult {
    bool acknowledged = false;
    int status = 0;
    std::string detail;
};

class HttpsBatchClient final {
public:
    HttpsBatchClient()
        : tls_(ssl::context::tls_client)
        , resolver_(io_)
        , response_buffer_(128 * 1024) {
        IoErrorCode ec;
        tls_.set_default_verify_paths(ec);
        if (ec) {
            LOG_WARN("access-log reporter: default CA paths unavailable: {}", ec.message());
        }
#ifdef _WIN32
        LoadWindowsCaCertificates(tls_);
#endif
        tls_.set_verify_mode(ssl::verify_peer);
    }

    SendResult Send(std::span<const uint8_t> body, std::string_view batch_id) {
        if (cancelled_.load(std::memory_order_acquire)) {
            return {.detail = "reporter stopping"};
        }
        io_.restart();
        auto result = net::co_spawn(
            io_, SendAsync(body, std::string(batch_id)), net::use_future);
        io_.run();
        try {
            return result.get();
        } catch (const std::exception& e) {
            Close();
            return {.detail = e.what()};
        } catch (...) {
            Close();
            return {.detail = "unknown HTTPS error"};
        }
    }

    void Cancel() noexcept {
        cancelled_.store(true, std::memory_order_release);
        net::post(io_, [this] {
            resolver_.cancel();
            Close();
        });
    }

private:
    net::awaitable<bool> EnsureConnected() {
        if (cancelled_.load(std::memory_order_acquire)) {
            co_return false;
        }
        if (stream_ && stream_->next_layer().is_open()) {
            co_return true;
        }

        Close();
        stream_ = std::make_unique<ssl::stream<tcp::socket>>(io_, tls_);
        stream_->set_verify_callback(
            ssl::host_name_verification(std::string(kServiceHost)));

        net::steady_timer timer(io_);
        timer.expires_after(kConnectTimeout);
        timer.async_wait([this](const IoErrorCode& ec) {
            if (!ec) {
                resolver_.cancel();
            }
        });

        IoErrorCode ec;
        auto endpoints = co_await resolver_.async_resolve(
            std::string(kServiceHost),
            std::string(kServicePort),
            net::redirect_error(net::use_awaitable, ec));
        timer.cancel();
        if (ec) {
            Close();
            co_return false;
        }

        timer.expires_after(kConnectTimeout);
        timer.async_wait([this](const IoErrorCode& timeout_ec) {
            if (!timeout_ec && stream_) {
                IoErrorCode ignored;
                stream_->next_layer().cancel(ignored);
            }
        });
        co_await net::async_connect(
            stream_->next_layer(),
            endpoints,
            net::redirect_error(net::use_awaitable, ec));
        timer.cancel();
        if (ec) {
            Close();
            co_return false;
        }

        stream_->next_layer().set_option(tcp::no_delay(true), ec);
        if (!SSL_set_tlsext_host_name(
                stream_->native_handle(), kServiceHost.data())) {
            Close();
            co_return false;
        }

        timer.expires_after(kConnectTimeout);
        timer.async_wait([this](const IoErrorCode& timeout_ec) {
            if (!timeout_ec && stream_) {
                IoErrorCode ignored;
                stream_->next_layer().cancel(ignored);
            }
        });
        co_await stream_->async_handshake(
            ssl::stream_base::client,
            net::redirect_error(net::use_awaitable, ec));
        timer.cancel();
        if (ec) {
            Close();
            co_return false;
        }
        co_return true;
    }

    net::awaitable<bool> TimedWrite(
        std::span<const net::const_buffer> buffers) {
        net::steady_timer timer(io_);
        timer.expires_after(kRequestTimeout);
        timer.async_wait([this](const IoErrorCode& timeout_ec) {
            if (!timeout_ec && stream_) {
                IoErrorCode ignored;
                stream_->next_layer().cancel(ignored);
            }
        });
        IoErrorCode ec;
        co_await net::async_write(
            *stream_, buffers, net::redirect_error(net::use_awaitable, ec));
        timer.cancel();
        co_return !ec;
    }

    net::awaitable<bool> EnsureBuffered(size_t bytes) {
        if (response_buffer_.size() >= bytes) {
            co_return true;
        }
        net::steady_timer timer(io_);
        timer.expires_after(kRequestTimeout);
        timer.async_wait([this](const IoErrorCode& timeout_ec) {
            if (!timeout_ec && stream_) {
                IoErrorCode ignored;
                stream_->next_layer().cancel(ignored);
            }
        });
        IoErrorCode ec;
        co_await net::async_read(
            *stream_,
            response_buffer_,
            net::transfer_exactly(bytes - response_buffer_.size()),
            net::redirect_error(net::use_awaitable, ec));
        timer.cancel();
        co_return !ec;
    }

    net::awaitable<bool> ReadUntil(std::string_view delimiter) {
        net::steady_timer timer(io_);
        timer.expires_after(kRequestTimeout);
        timer.async_wait([this](const IoErrorCode& timeout_ec) {
            if (!timeout_ec && stream_) {
                IoErrorCode ignored;
                stream_->next_layer().cancel(ignored);
            }
        });
        IoErrorCode ec;
        co_await net::async_read_until(
            *stream_,
            response_buffer_,
            delimiter,
            net::redirect_error(net::use_awaitable, ec));
        timer.cancel();
        co_return !ec;
    }

    net::awaitable<std::optional<std::string>> ReadChunkedBody() {
        std::string body;
        while (body.size() <= 64 * 1024) {
            if (!co_await ReadUntil("\r\n")) {
                co_return std::nullopt;
            }
            std::istream input(&response_buffer_);
            std::string size_line;
            std::getline(input, size_line);
            if (!size_line.empty() && size_line.back() == '\r') {
                size_line.pop_back();
            }
            if (const auto extension = size_line.find(';');
                extension != std::string::npos) {
                size_line.resize(extension);
            }
            size_t chunk_size = 0;
            const auto parsed = std::from_chars(
                size_line.data(), size_line.data() + size_line.size(),
                chunk_size, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != size_line.data() + size_line.size()) {
                co_return std::nullopt;
            }
            if (chunk_size == 0) {
                while (true) {
                    if (!co_await ReadUntil("\r\n")) {
                        co_return std::nullopt;
                    }
                    std::string trailer;
                    std::getline(input, trailer);
                    if (trailer == "\r" || trailer.empty()) {
                        co_return body;
                    }
                }
            }
            if (chunk_size > 64 * 1024 - body.size() ||
                !co_await EnsureBuffered(chunk_size + 2)) {
                co_return std::nullopt;
            }
            const size_t offset = body.size();
            body.resize(offset + chunk_size);
            input.read(body.data() + offset, static_cast<std::streamsize>(chunk_size));
            char crlf[2]{};
            input.read(crlf, 2);
            if (input.gcount() != 2 || crlf[0] != '\r' || crlf[1] != '\n') {
                co_return std::nullopt;
            }
        }
        co_return std::nullopt;
    }

    net::awaitable<std::optional<HttpResponse>> ReadResponse() {
        if (!co_await ReadUntil("\r\n\r\n")) {
            co_return std::nullopt;
        }

        HttpResponse response;
        std::istream input(&response_buffer_);
        std::string status_line;
        std::getline(input, status_line);
        if (!status_line.empty() && status_line.back() == '\r') {
            status_line.pop_back();
        }
        std::istringstream status(status_line);
        std::string version;
        status >> version >> response.status;
        if (!status || version.rfind("HTTP/", 0) != 0) {
            co_return std::nullopt;
        }

        std::string line;
        while (std::getline(input, line)) {
            if (line == "\r" || line.empty()) {
                break;
            }
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const size_t colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            const std::string name = LowerCopy(TrimCopy(
                std::string_view(line).substr(0, colon)));
            const std::string value = LowerCopy(TrimCopy(
                std::string_view(line).substr(colon + 1)));
            if (name == "content-length") {
                size_t length = 0;
                const auto parsed = std::from_chars(
                    value.data(), value.data() + value.size(), length);
                if (parsed.ec != std::errc{} ||
                    parsed.ptr != value.data() + value.size() ||
                    length > 64 * 1024) {
                    co_return std::nullopt;
                }
                response.content_length = length;
            } else if (name == "transfer-encoding" &&
                       value.find("chunked") != std::string::npos) {
                response.chunked = true;
            } else if (name == "connection" && value == "close") {
                response.connection_close = true;
            }
        }

        if (response.chunked) {
            auto body = co_await ReadChunkedBody();
            if (!body) {
                co_return std::nullopt;
            }
            response.body = std::move(*body);
        } else if (response.content_length) {
            if (!co_await EnsureBuffered(*response.content_length)) {
                co_return std::nullopt;
            }
            response.body.resize(*response.content_length);
            input.read(
                response.body.data(),
                static_cast<std::streamsize>(*response.content_length));
            if (static_cast<size_t>(input.gcount()) != *response.content_length) {
                co_return std::nullopt;
            }
        }
        co_return response;
    }

    net::awaitable<SendResult> SendAsync(
        std::span<const uint8_t> body,
        std::string batch_id) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (cancelled_.load(std::memory_order_acquire)) {
                co_return SendResult{.detail = "reporter stopping"};
            }
            if (!co_await EnsureConnected()) {
                continue;
            }

            const std::string headers = std::format(
                "POST {} HTTP/1.1\r\n"
                "Host: {}\r\n"
                "Authorization: Bearer {}\r\n"
                "Content-Type: application/x-protobuf\r\n"
                "Content-Encoding: zstd\r\n"
                "Content-Length: {}\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: cnode-access-log/1\r\n"
                "X-Cnode-Server-Id: {}\r\n"
                "X-Cnode-Batch-Id: {}\r\n"
                "X-Cnode-Schema-Version: 1\r\n\r\n",
                kBatchTarget,
                kServiceHost,
                kBearerToken,
                body.size(),
                server_id_,
                batch_id);
            const std::array<net::const_buffer, 2> buffers{
                net::buffer(headers),
                net::buffer(body.data(), body.size()),
            };
            if (!co_await TimedWrite(buffers)) {
                Close();
                continue;
            }

            auto response = co_await ReadResponse();
            if (!response) {
                Close();
                continue;
            }
            if (response->connection_close) {
                Close();
            }

            SendResult result;
            result.status = response->status;
            result.detail = response->body.substr(0, 512);
            if (response->status == 200 || response->status == 409) {
                std::string compact;
                compact.reserve(response->body.size());
                for (unsigned char ch : response->body) {
                    if (!std::isspace(ch)) {
                        compact.push_back(static_cast<char>(std::tolower(ch)));
                    }
                }
                const bool accepted =
                    compact.find("\"accepted\":true") != std::string::npos ||
                    response->status == 409;
                const bool matching_batch =
                    compact.find(LowerCopy(batch_id)) != std::string::npos;
                result.acknowledged = accepted && matching_batch;
            }
            co_return result;
        }
        co_return SendResult{.detail = "connect/write/read failed"};
    }

    void Close() noexcept {
        if (stream_) {
            IoErrorCode ignored;
            stream_->next_layer().cancel(ignored);
            stream_->next_layer().shutdown(tcp::socket::shutdown_both, ignored);
            stream_->next_layer().close(ignored);
            stream_.reset();
        }
        response_buffer_.consume(response_buffer_.size());
    }

    net::io_context io_;
    ssl::context tls_;
    tcp::resolver resolver_;
    std::unique_ptr<ssl::stream<tcp::socket>> stream_;
    net::streambuf response_buffer_;
    std::string server_id_ = ResolveServerId();
    std::atomic_bool cancelled_{false};
};

class Spool final {
public:
    struct Entry {
        std::filesystem::path path;
        std::string batch_id;
        uint64_t bytes = 0;
        uint64_t event_count = 0;
    };

    explicit Spool(std::filesystem::path path)
        : path_(std::move(path)) {}

    bool Initialize() {
        std::error_code ec;
        std::filesystem::create_directories(path_, ec);
        if (ec) {
            LOG_ERROR("access-log reporter: cannot create spool {}: {}",
                      path_.string(), ec.message());
            return false;
        }
#ifndef _WIN32
        std::filesystem::permissions(
            path_,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec);
        ec.clear();
#endif

        std::vector<Entry> loaded;
        for (std::filesystem::directory_iterator it(path_, ec), end;
             !ec && it != end;
             it.increment(ec)) {
            if (!it->is_regular_file(ec)) {
                ec.clear();
                continue;
            }
            const auto path = it->path();
            if (path.extension() == ".tmp") {
                std::filesystem::remove(path, ec);
                ec.clear();
                continue;
            }
            if (path.extension() != ".batch") {
                continue;
            }
            const std::string stem = path.stem().string();
            const size_t underscore = stem.rfind('_');
            if (underscore == std::string::npos ||
                !IsHexId(std::string_view(stem).substr(underscore + 1))) {
                LOG_WARN("access-log reporter: ignoring malformed spool file {}",
                         path.string());
                continue;
            }
            uint64_t event_count = 0;
            if (underscore > 0) {
                const size_t count_separator = stem.rfind('_', underscore - 1);
                if (count_separator != std::string::npos) {
                    const std::string_view count_text(stem.data() + count_separator + 1,
                                                      underscore - count_separator - 1);
                    const auto parsed = std::from_chars(
                        count_text.data(), count_text.data() + count_text.size(),
                        event_count);
                    if (parsed.ec != std::errc{} ||
                        parsed.ptr != count_text.data() + count_text.size()) {
                        event_count = 0;
                    }
                }
            }
            const uint64_t size = std::filesystem::file_size(path, ec);
            if (ec || size > kMaxSpoolFileBytes) {
                LOG_WARN("access-log reporter: ignoring invalid spool file {}",
                         path.string());
                ec.clear();
                continue;
            }
            loaded.push_back({
                .path = path,
                .batch_id = stem.substr(underscore + 1),
                .bytes = size,
                .event_count = event_count,
            });
        }
        if (ec) {
            LOG_ERROR("access-log reporter: cannot scan spool {}: {}",
                      path_.string(), ec.message());
            return false;
        }
        std::ranges::sort(loaded, {}, [](const Entry& entry) {
            return entry.path.filename().string();
        });
        for (auto& entry : loaded) {
            bytes_ += entry.bytes;
            entries_.push_back(std::move(entry));
        }
        uint64_t evicted_events = 0;
        while (bytes_ > kMaxSpoolBytes && !entries_.empty()) {
            std::filesystem::remove(entries_.front().path, ec);
            if (ec) {
                LOG_ERROR(
                    "access-log reporter: cannot enforce spool limit for {}: {}",
                    entries_.front().path.string(),
                    ec.message());
                return false;
            }
            evicted_events += entries_.front().event_count;
            bytes_ -= entries_.front().bytes;
            entries_.pop_front();
        }
        if (evicted_events > 0) {
            LOG_WARN(
                "access-log reporter: startup spool limit evicted_events={}",
                evicted_events);
        }
        initialized_ = true;
        return true;
    }

    bool Write(std::span<const uint8_t> payload,
               std::string batch_id,
               uint64_t event_count,
               uint64_t& evicted_events) {
        evicted_events = 0;
        if (!initialized_ || payload.empty() ||
            payload.size() > kMaxSpoolFileBytes ||
            payload.size() > kMaxSpoolBytes) {
            return false;
        }

        while (bytes_ + payload.size() > kMaxSpoolBytes && !entries_.empty()) {
            std::error_code ec;
            std::filesystem::remove(entries_.front().path, ec);
            if (ec) {
                return false;
            }
            evicted_events += entries_.front().event_count;
            bytes_ -= entries_.front().bytes;
            entries_.pop_front();
        }

        const std::string filename = std::format(
            "{:020}_{:010}_{}.batch", NowMicros(), event_count, batch_id);
        const auto final_path = path_ / filename;
        auto tmp_path = final_path;
        tmp_path += ".tmp";

        if (!DurableWrite(tmp_path, payload)) {
            std::error_code ignored;
            std::filesystem::remove(tmp_path, ignored);
            return false;
        }

        std::error_code ec;
        std::filesystem::rename(tmp_path, final_path, ec);
        if (ec) {
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
        SyncDirectory(path_);

        entries_.push_back({
            .path = final_path,
            .batch_id = std::move(batch_id),
            .bytes = payload.size(),
            .event_count = event_count,
        });
        bytes_ += payload.size();
        return true;
    }

    [[nodiscard]] bool Empty() const noexcept {
        return entries_.empty();
    }

    [[nodiscard]] uint64_t Bytes() const noexcept {
        return bytes_;
    }

    [[nodiscard]] const Entry* Front() const noexcept {
        return entries_.empty() ? nullptr : &entries_.front();
    }

    std::optional<std::vector<uint8_t>> ReadFront() const {
        const Entry* entry = Front();
        if (!entry || entry->bytes > kMaxSpoolFileBytes) {
            return std::nullopt;
        }
        std::ifstream input(entry->path, std::ios::binary);
        if (!input) {
            return std::nullopt;
        }
        std::vector<uint8_t> data(static_cast<size_t>(entry->bytes));
        if (!data.empty()) {
            input.read(
                reinterpret_cast<char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        }
        if (!input || static_cast<size_t>(input.gcount()) != data.size()) {
            return std::nullopt;
        }
        return data;
    }

    bool AcknowledgeFront() {
        if (entries_.empty()) {
            return false;
        }
        std::error_code ec;
        std::filesystem::remove(entries_.front().path, ec);
        if (ec) {
            return false;
        }
        bytes_ -= entries_.front().bytes;
        entries_.pop_front();
        return true;
    }

    void QuarantineFront() {
        if (entries_.empty()) {
            return;
        }
        auto bad_path = entries_.front().path;
        bad_path.replace_extension(".bad");
        std::error_code ec;
        std::filesystem::rename(entries_.front().path, bad_path, ec);
        bytes_ -= entries_.front().bytes;
        entries_.pop_front();
    }

private:
    std::filesystem::path path_;
    bool initialized_ = false;
    uint64_t bytes_ = 0;
    std::deque<Entry> entries_;
};

}  // namespace

class Reporter::Impl final {
public:
    Impl()
        : queue_(kQueueCapacity)
        , sources_(std::make_shared<const std::vector<Source>>())
        , boot_id_(MakeBootId())
        , server_id_(ResolveServerId()) {}

    ~Impl() {
        Shutdown();
    }

    bool Initialize(const std::filesystem::path& log_dir) {
        std::lock_guard lock(lifecycle_mutex_);
        if (initialized_.load(std::memory_order_acquire)) {
            return true;
        }
        if (stopping_.load(std::memory_order_acquire)) {
            return false;
        }
        spool_path_ = ResolveSpoolPath(log_dir);
        thread_ = std::thread([this] { Run(); });
        initialized_.store(true, std::memory_order_release);
        return true;
    }

    uint32_t RegisterSource(Source source) {
        if (stopping_.load(std::memory_order_acquire) || source.node_id == 0) {
            return 0;
        }
        source.panel_api_host = NormalizePanelApiHost(source.panel_api_host);
        source.node_type = LowerCopy(TrimCopy(source.node_type));
        source.panel_name = TrimCopy(source.panel_name);
        if (source.panel_api_host.empty() || source.node_type.empty()) {
            return 0;
        }
        if (source.panel_name.empty()) {
            source.panel_name = source.panel_api_host;
        }

        std::string key;
        key.reserve(source.panel_api_host.size() + source.node_type.size() + 32);
        key.append(source.panel_api_host);
        key.push_back('\0');
        key.append(source.node_type);
        key.push_back('\0');
        key.append(std::to_string(source.node_id));

        std::lock_guard lock(source_mutex_);
        if (const auto it = source_refs_.find(key); it != source_refs_.end()) {
            return it->second;
        }
        const auto current = sources_.load(std::memory_order_acquire);
        if (current->size() >= std::numeric_limits<uint32_t>::max()) {
            return 0;
        }
        auto next = std::make_shared<std::vector<Source>>(*current);
        next->push_back(std::move(source));
        const uint32_t ref = static_cast<uint32_t>(next->size());
        source_refs_.emplace(std::move(key), ref);
        sources_.store(std::move(next), std::memory_order_release);
        return ref;
    }

    bool Submit(Event event) noexcept {
        if (event.source_ref == 0 ||
            !initialized_.load(std::memory_order_acquire) ||
            stopping_.load(std::memory_order_acquire)) {
            return false;
        }

        const size_t previous = queued_.fetch_add(1, std::memory_order_acq_rel);
        if (previous >= kQueueCapacity) {
            queued_.fetch_sub(1, std::memory_order_release);
            dropped_events_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if (!queue_.try_enqueue(std::move(event))) {
            queued_.fetch_sub(1, std::memory_order_release);
            dropped_events_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        wake_.notify_one();
        return true;
    }

    void Shutdown() noexcept {
        if (stopping_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        if (initialized_.load(std::memory_order_acquire)) {
            client_.Cancel();
        }
        wake_.notify_all();
        if (thread_.joinable()) {
            thread_.join();
        }
    }

private:
    void PersistRange(
        Spool& spool,
        std::span<const detail::SequencedEvent> events,
        std::span<const Source> sources) {
        if (events.empty()) {
            return;
        }
        auto batch = detail::EncodeBatch(events, sources, server_id_, boot_id_);
        if (batch.protobuf.empty()) {
            dropped_events_.fetch_add(events.size(), std::memory_order_relaxed);
            return;
        }
        if (batch.protobuf.size() > kMaxBatchProtobufBytes && events.size() > 1) {
            const size_t middle = events.size() / 2;
            PersistRange(spool, events.first(middle), sources);
            PersistRange(spool, events.subspan(middle), sources);
            return;
        }

        auto compressed = detail::CompressZstd(batch.protobuf);
        if (compressed.empty()) {
            dropped_events_.fetch_add(events.size(), std::memory_order_relaxed);
            LOG_ERROR("access-log reporter: zstd compression failed events={}", events.size());
            return;
        }

        uint64_t evicted_events = 0;
        if (!spool.Write(
                compressed,
                detail::HexId(batch.batch_id),
                events.size(),
                evicted_events)) {
            dropped_events_.fetch_add(events.size(), std::memory_order_relaxed);
            LOG_ERROR("access-log reporter: spool write failed events={} bytes={}",
                      events.size(), compressed.size());
            return;
        }
        if (evicted_events > 0) {
            evicted_events_.fetch_add(evicted_events, std::memory_order_relaxed);
        }
    }

    void DrainOneBatch(Spool& spool, std::vector<Event>& buffer) {
        const size_t count = queue_.try_dequeue_bulk(buffer.data(), buffer.size());
        if (count == 0) {
            return;
        }
        queued_.fetch_sub(count, std::memory_order_release);

        const auto sources = sources_.load(std::memory_order_acquire);
        std::vector<detail::SequencedEvent> sequenced;
        sequenced.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            Event event = std::move(buffer[i]);
            if (event.source_ref == 0 || event.source_ref > sources->size()) {
                dropped_events_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            sequenced.push_back({
                .sequence = next_sequence_++,
                .event = std::move(event),
            });
        }
        PersistRange(spool, sequenced, *sources);
    }

    void ReportDropsIfNeeded() {
        const uint64_t dropped = dropped_events_.load(std::memory_order_relaxed);
        const uint64_t evicted = evicted_events_.load(std::memory_order_relaxed);
        if (dropped != last_reported_dropped_ || evicted != last_reported_evicted_) {
            LOG_WARN(
                "access-log reporter: loss counters dropped_events={} evicted_events={}",
                dropped,
                evicted);
            last_reported_dropped_ = dropped;
            last_reported_evicted_ = evicted;
        }
    }

    void Run() noexcept {
        Spool spool(spool_path_);
        const bool spool_ready = spool.Initialize();
        if (!spool_ready) {
            LOG_ERROR("access-log reporter disabled persistence path={}",
                      spool_path_.string());
        } else {
            LOG_INFO(
                "access-log reporter ready endpoint={} target={} spool={} pending_bytes={}",
                kServiceBaseUrl,
                kBatchTarget,
                spool_path_.string(),
                spool.Bytes());
        }

        std::vector<Event> dequeue_buffer(kMaxBatchEvents);
        auto retry_delay = kInitialRetry;
        auto next_send = std::chrono::steady_clock::now();
        auto next_send_warning = std::chrono::steady_clock::time_point::min();
        auto next_drop_report = std::chrono::steady_clock::now() + 60s;
        std::optional<std::chrono::steady_clock::time_point> first_queued_at;

        try {
            while (!stopping_.load(std::memory_order_acquire)) {
                const auto now = std::chrono::steady_clock::now();
                const size_t queued = queued_.load(std::memory_order_acquire);
                if (queued > 0 && !first_queued_at) {
                    first_queued_at = now;
                }
                if (spool_ready && queued > 0 &&
                    (queued >= kMaxBatchEvents ||
                     now - *first_queued_at >= kFlushInterval)) {
                    DrainOneBatch(spool, dequeue_buffer);
                    first_queued_at = queued_.load(std::memory_order_acquire) > 0
                        ? std::optional{std::chrono::steady_clock::now()}
                        : std::nullopt;
                }

                if (spool_ready && !spool.Empty() && now >= next_send) {
                    const Spool::Entry* entry = spool.Front();
                    auto payload = spool.ReadFront();
                    if (!entry || !payload) {
                        if (entry) {
                            LOG_ERROR("access-log reporter: quarantining unreadable batch {}",
                                      entry->path.string());
                        }
                        spool.QuarantineFront();
                        next_send = now;
                        continue;
                    }

                    const std::string batch_id = entry->batch_id;
                    const SendResult sent = client_.Send(*payload, batch_id);
                    if (sent.acknowledged) {
                        if (!spool.AcknowledgeFront()) {
                            LOG_ERROR("access-log reporter: cannot remove acknowledged batch {}",
                                      batch_id);
                            next_send = now + retry_delay;
                        } else {
                            retry_delay = kInitialRetry;
                            next_send = now;
                            next_send_warning = std::chrono::steady_clock::time_point::min();
                        }
                    } else {
                        if (now >= next_send_warning) {
                            LOG_WARN(
                                "access-log reporter: service unavailable batch={} status={} retry_ms={} detail={}",
                                batch_id,
                                sent.status,
                                retry_delay.count(),
                                sent.detail);
                            next_send_warning = now + 60s;
                        }
                        const auto jitter = std::chrono::milliseconds(
                            static_cast<int>(next_sequence_ % 251));
                        next_send = now + retry_delay + jitter;
                        retry_delay = std::min(retry_delay * 2, kMaxRetry);
                    }
                }

                if (now >= next_drop_report) {
                    ReportDropsIfNeeded();
                    next_drop_report = now + 60s;
                }

                auto wake_at = now + 250ms;
                if (first_queued_at) {
                    wake_at = std::min(wake_at, *first_queued_at + kFlushInterval);
                }
                if (spool_ready && !spool.Empty()) {
                    wake_at = std::min(wake_at, next_send);
                }
                std::unique_lock lock(wake_mutex_);
                wake_.wait_until(lock, wake_at, [this] {
                    return stopping_.load(std::memory_order_acquire) ||
                           queued_.load(std::memory_order_acquire) >= kMaxBatchEvents;
                });
            }

            if (spool_ready) {
                while (queued_.load(std::memory_order_acquire) > 0) {
                    DrainOneBatch(spool, dequeue_buffer);
                }
            } else {
                Event dropped;
                while (queue_.try_dequeue(dropped)) {
                    queued_.fetch_sub(1, std::memory_order_release);
                    dropped_events_.fetch_add(1, std::memory_order_relaxed);
                }
            }
            ReportDropsIfNeeded();
        } catch (const std::exception& e) {
            LOG_ERROR("access-log reporter thread failed: {}", e.what());
        } catch (...) {
            LOG_ERROR("access-log reporter thread failed: unknown");
        }
    }

    moodycamel::ConcurrentQueue<Event> queue_;
    std::atomic<size_t> queued_{0};
    std::atomic<uint64_t> dropped_events_{0};
    std::atomic<uint64_t> evicted_events_{0};

    std::mutex source_mutex_;
    std::unordered_map<std::string, uint32_t> source_refs_;
    std::atomic<std::shared_ptr<const std::vector<Source>>> sources_;

    detail::Id128 boot_id_{};
    std::string server_id_;
    uint64_t next_sequence_ = 1;
    uint64_t last_reported_dropped_ = 0;
    uint64_t last_reported_evicted_ = 0;

    std::atomic_bool stopping_{false};
    std::atomic_bool initialized_{false};
    std::mutex lifecycle_mutex_;
    std::filesystem::path spool_path_;
    HttpsBatchClient client_;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    std::thread thread_;
};

Reporter& Reporter::Instance() {
    static Reporter reporter;
    return reporter;
}

Reporter::Reporter()
    : impl_(std::make_unique<Impl>()) {}

Reporter::~Reporter() = default;

bool Reporter::Initialize(const std::filesystem::path& log_dir) {
    return impl_->Initialize(log_dir);
}

uint32_t Reporter::RegisterSource(Source source) {
    return impl_->RegisterSource(std::move(source));
}

bool Reporter::Submit(Event event) noexcept {
    return impl_->Submit(std::move(event));
}

void Reporter::Shutdown() noexcept {
    impl_->Shutdown();
}

}  // namespace acpp::accesslog
