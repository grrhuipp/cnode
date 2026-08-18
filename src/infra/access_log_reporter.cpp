#include "acppnode/infra/access_log_reporter.hpp"

#include "access_log_ack.hpp"
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
#include <deque>
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
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif

namespace acpp::accesslog {

namespace {

using namespace std::chrono_literals;
namespace ssl = net::ssl;

constexpr std::string_view kBearerToken =
    "51aba8b656f39b65d249ae6b2145fe07c1103dc64037b55d4c9d2b174d03ecb3";
constexpr size_t kMaxBatchEvents = 1000;
// Event owns many strings and is intentionally preallocated so Submit stays
// non-blocking. Eight full flush batches absorb short bursts without keeping
// tens of thousands of these large objects resident while the node is idle.
constexpr size_t kEventQueueCapacity = 8 * 1024;
static_assert(kEventQueueCapacity >= 8 * kMaxBatchEvents);
constexpr size_t kMaxBatchProtobufBytes = 1024 * 1024;
constexpr uint64_t kMaxPendingBatchBytesPerStream = 32ULL * 1024 * 1024;
constexpr size_t kMaxBatchPayloadBytes = 8 * 1024 * 1024;
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

    SendResult Send(std::span<const uint8_t> body,
                    std::string_view batch_id,
                    std::string_view target) {
        if (cancelled_.load(std::memory_order_acquire)) {
            return {.detail = "reporter stopping"};
        }
        io_.restart();
        auto result = net::co_spawn(
            io_,
            SendAsync(body, std::string(batch_id), std::string(target)),
            net::use_future);
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
        std::string batch_id,
        std::string target) {
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
                target,
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
            result.acknowledged = detail::IsBatchAcknowledged(
                response->status, response->body, batch_id);
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

class PendingBatchQueue final {
public:
    struct Entry {
        std::vector<uint8_t> payload;
        std::string batch_id;
        uint64_t event_count = 0;
    };

    bool Push(std::vector<uint8_t> payload,
              std::string batch_id,
              uint64_t event_count,
              uint64_t& evicted_events) {
        evicted_events = 0;
        if (payload.empty() ||
            payload.size() > kMaxBatchPayloadBytes ||
            payload.size() > kMaxPendingBatchBytesPerStream) {
            return false;
        }

        while (bytes_ + payload.size() > kMaxPendingBatchBytesPerStream &&
               !entries_.empty()) {
            evicted_events += entries_.front().event_count;
            bytes_ -= entries_.front().payload.size();
            event_count_ -= entries_.front().event_count;
            entries_.pop_front();
        }

        const size_t payload_size = payload.size();
        entries_.push_back({
            .payload = std::move(payload),
            .batch_id = std::move(batch_id),
            .event_count = event_count,
        });
        bytes_ += payload_size;
        event_count_ += event_count;
        return true;
    }

    [[nodiscard]] bool Empty() const noexcept {
        return entries_.empty();
    }

    [[nodiscard]] uint64_t EventCount() const noexcept {
        return event_count_;
    }

    [[nodiscard]] const Entry* Front() const noexcept {
        return entries_.empty() ? nullptr : &entries_.front();
    }

    void PopFront() noexcept {
        if (entries_.empty()) {
            return;
        }
        bytes_ -= entries_.front().payload.size();
        event_count_ -= entries_.front().event_count;
        entries_.pop_front();
    }

    void Clear() noexcept {
        entries_.clear();
        bytes_ = 0;
        event_count_ = 0;
    }

private:
    uint64_t bytes_ = 0;
    uint64_t event_count_ = 0;
    std::deque<Entry> entries_;
};

}  // namespace

class Reporter::Impl final {
public:
    Impl()
        : queue_(kEventQueueCapacity)
        , sources_(std::make_shared<const std::vector<Source>>())
        , boot_id_(MakeBootId())
        , server_id_(ResolveServerId()) {}

    ~Impl() {
        Shutdown();
    }

    bool Initialize() {
        std::lock_guard lock(lifecycle_mutex_);
        if (initialized_.load(std::memory_order_acquire)) {
            return true;
        }
        if (stopping_.load(std::memory_order_acquire)) {
            return false;
        }
        try {
            thread_ = std::thread([this] { Run(); });
        } catch (const std::exception& e) {
            LOG_ERROR("access-log reporter thread start failed: {}", e.what());
            return false;
        } catch (...) {
            LOG_ERROR("access-log reporter thread start failed: unknown");
            return false;
        }
        initialized_.store(true, std::memory_order_release);
        LOG_INFO(
            "access-log reporter ready endpoint={} access_target={} error_target={} "
            "pending_memory_limit_per_stream={}",
            kServiceBaseUrl,
            kAccessBatchTarget,
            kErrorBatchTarget,
            kMaxPendingBatchBytesPerStream);
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
        if (previous >= kEventQueueCapacity) {
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
    void EnqueueRange(
        PendingBatchQueue& pending,
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
            EnqueueRange(pending, events.first(middle), sources);
            EnqueueRange(pending, events.subspan(middle), sources);
            return;
        }

        auto compressed = detail::CompressZstd(batch.protobuf);
        if (compressed.empty()) {
            dropped_events_.fetch_add(events.size(), std::memory_order_relaxed);
            LOG_ERROR("access-log reporter: zstd compression failed events={}", events.size());
            return;
        }

        uint64_t evicted_events = 0;
        const size_t compressed_size = compressed.size();
        if (!pending.Push(
                std::move(compressed),
                detail::HexId(batch.batch_id),
                events.size(),
                evicted_events)) {
            dropped_events_.fetch_add(events.size(), std::memory_order_relaxed);
            LOG_ERROR(
                "access-log reporter: pending batch rejected events={} bytes={}",
                events.size(),
                compressed_size);
            return;
        }
        if (evicted_events > 0) {
            evicted_events_.fetch_add(evicted_events, std::memory_order_relaxed);
        }
    }

    void DrainOneBatch(PendingBatchQueue& access_pending,
                       PendingBatchQueue& error_pending,
                       std::vector<Event>& buffer) {
        const size_t count = queue_.try_dequeue_bulk(buffer.data(), buffer.size());
        if (count == 0) {
            return;
        }
        queued_.fetch_sub(count, std::memory_order_release);

        const auto sources = sources_.load(std::memory_order_acquire);
        std::vector<detail::SequencedEvent> access_events;
        std::vector<detail::SequencedEvent> error_events;
        access_events.reserve(count);
        error_events.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            Event event = std::move(buffer[i]);
            if (event.source_ref == 0 || event.source_ref > sources->size()) {
                dropped_events_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            auto& destination = event.error_code == ErrorCode::OK
                ? access_events
                : error_events;
            destination.push_back({
                .sequence = next_sequence_++,
                .event = std::move(event),
            });
        }
        EnqueueRange(access_pending, access_events, *sources);
        EnqueueRange(error_pending, error_events, *sources);
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
        PendingBatchQueue& access_pending = access_pending_;
        PendingBatchQueue& error_pending = error_pending_;

        struct StreamState {
            PendingBatchQueue* pending;
            std::string_view target;
            std::chrono::milliseconds retry_delay{kInitialRetry};
            std::chrono::steady_clock::time_point next_send{
                std::chrono::steady_clock::now()};
            std::chrono::steady_clock::time_point next_warning{
                std::chrono::steady_clock::time_point::min()};
        };
        StreamState access_stream{.pending = &access_pending,
                                  .target = kAccessBatchTarget};
        StreamState error_stream{.pending = &error_pending,
                                 .target = kErrorBatchTarget};

        std::vector<Event> dequeue_buffer(kMaxBatchEvents);
        auto next_drop_report = std::chrono::steady_clock::now() + 60s;
        std::optional<std::chrono::steady_clock::time_point> first_queued_at;

        auto send_front = [this](StreamState& stream,
                                 std::chrono::steady_clock::time_point now) {
            if (now < stream.next_send) {
                return;
            }
            const PendingBatchQueue::Entry* entry = stream.pending->Front();
            if (!entry) {
                return;
            }

            const std::string batch_id = entry->batch_id;
            const uint64_t event_count = entry->event_count;
            const SendResult sent = client_.Send(
                entry->payload, batch_id, stream.target);
            if (sent.acknowledged) {
                stream.pending->PopFront();
                stream.retry_delay = kInitialRetry;
                stream.next_send = now;
                stream.next_warning =
                    std::chrono::steady_clock::time_point::min();
            } else if (sent.status == 400) {
                LOG_ERROR(
                    "access-log reporter: service rejected invalid target={} "
                    "batch={} events={} detail={}",
                    stream.target,
                    batch_id,
                    event_count,
                    sent.detail);
                stream.pending->PopFront();
                dropped_events_.fetch_add(event_count, std::memory_order_relaxed);
                stream.retry_delay = kInitialRetry;
                stream.next_send = now;
                stream.next_warning =
                    std::chrono::steady_clock::time_point::min();
            } else {
                if (now >= stream.next_warning) {
                    LOG_WARN(
                        "access-log reporter: service unavailable target={} batch={} "
                        "status={} retry_ms={} detail={}",
                        stream.target,
                        batch_id,
                        sent.status,
                        stream.retry_delay.count(),
                        sent.detail);
                    stream.next_warning = now + 60s;
                }
                const auto jitter = std::chrono::milliseconds(
                    static_cast<int>(next_sequence_ % 251));
                stream.next_send = now + stream.retry_delay + jitter;
                stream.retry_delay = std::min(stream.retry_delay * 2, kMaxRetry);
            }
        };

        try {
            while (!stopping_.load(std::memory_order_acquire)) {
                const auto now = std::chrono::steady_clock::now();
                const size_t queued = queued_.load(std::memory_order_acquire);
                if (queued > 0 && !first_queued_at) {
                    first_queued_at = now;
                }
                if (queued > 0 &&
                    (queued >= kMaxBatchEvents ||
                     now - *first_queued_at >= kFlushInterval)) {
                    DrainOneBatch(access_pending, error_pending, dequeue_buffer);
                    first_queued_at = queued_.load(std::memory_order_acquire) > 0
                        ? std::optional{std::chrono::steady_clock::now()}
                        : std::nullopt;
                }

                send_front(access_stream, now);
                send_front(error_stream, now);

                if (now >= next_drop_report) {
                    ReportDropsIfNeeded();
                    next_drop_report = now + 60s;
                }

                auto wake_at = now + 250ms;
                if (first_queued_at) {
                    wake_at = std::min(wake_at, *first_queued_at + kFlushInterval);
                }
                if (!access_pending.Empty()) {
                    wake_at = std::min(wake_at, access_stream.next_send);
                }
                if (!error_pending.Empty()) {
                    wake_at = std::min(wake_at, error_stream.next_send);
                }
                std::unique_lock lock(wake_mutex_);
                wake_.wait_until(lock, wake_at, [this] {
                    return stopping_.load(std::memory_order_acquire) ||
                           queued_.load(std::memory_order_acquire) >= kMaxBatchEvents;
                });
            }

            uint64_t shutdown_dropped =
                access_pending.EventCount() + error_pending.EventCount();
            while (queued_.load(std::memory_order_acquire) > 0) {
                const size_t count = queue_.try_dequeue_bulk(
                    dequeue_buffer.data(), dequeue_buffer.size());
                if (count == 0) {
                    std::this_thread::yield();
                    continue;
                }
                queued_.fetch_sub(count, std::memory_order_release);
                shutdown_dropped += count;
            }
            if (shutdown_dropped > 0) {
                dropped_events_.fetch_add(
                    shutdown_dropped, std::memory_order_relaxed);
            }
            access_pending.Clear();
            error_pending.Clear();
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
    PendingBatchQueue access_pending_;
    PendingBatchQueue error_pending_;
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

bool Reporter::Initialize() {
    return impl_->Initialize();
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
