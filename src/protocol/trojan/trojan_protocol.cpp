#include "acppnode/protocol/trojan/trojan_protocol.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp::trojan {

// ============================================================================
// TrojanServerStream 实现
// ============================================================================

TrojanServerStream::TrojanServerStream(std::unique_ptr<AsyncStream> inner,
                                       TrojanUserManager& user_manager)
    : inner_(std::move(inner))
    , user_manager_(user_manager) {}

TrojanServerStream::~TrojanServerStream() = default;

cobalt::task<HandshakeResult> TrojanServerStream::DoHandshake(const std::string& tag, const std::string& client_ip) {
    if (handshake_done_) {
        co_return HandshakeResult{std::nullopt, HandshakeFailReason::UNKNOWN_ERROR};
    }

    // 握手总时长上限使用阶段 deadline，避免本地 timer handler 生命周期问题。
    auto handshake_deadline =
        inner_->StartPhaseDeadline(std::chrono::seconds(10));

    std::array<uint8_t, 8192> fallback_buf{};
    uint8_t* buf = fallback_buf.data();
    size_t buf_capacity = fallback_buf.size();

    size_t total = 0;

    while (total < buf_capacity) {
        size_t n = 0;
        try {
            n = co_await inner_->AsyncRead(net::buffer(buf + total, buf_capacity - total));
        } catch (const boost::system::system_error&) {
            if (inner_->ConsumePhaseDeadline() || handshake_deadline.Expired()) {
                inner_->ClearPhaseDeadline();
                LOG_ACCESS_DEBUG("[{}] Handshake timeout from {}", tag, client_ip);
                co_return HandshakeResult{std::nullopt, HandshakeFailReason::TIMEOUT};
            }
            throw;
        }

        if (n == 0) {
            inner_->ClearPhaseDeadline();
            LOG_ACCESS_DEBUG("[{}] Connection closed from {}", tag, client_ip);
            co_return HandshakeResult{std::nullopt, HandshakeFailReason::CONNECTION_CLOSED};
        }
        total += n;

        size_t consumed = 0;
        auto req = TrojanCodec::ParseRequest(buf, total, consumed);

        if (req) {
            inner_->ClearPhaseDeadline();

            // 验证用户（限定 tag，避免跨节点验证）
            if (!user_manager_.Validate(tag, req->password_hash)) {
                // 安全加固：不记录 hash 值，只记录来源 IP 用于安全审计
                LOG_CONN_FAIL("[{}] Auth failed from {}: invalid password",
                         tag, client_ip);
                co_return HandshakeResult{std::nullopt, HandshakeFailReason::AUTH_FAILED};
            }

            auto user = user_manager_.FindUser(tag, req->password_hash);
            if (user) {
                user_info_ = *user;
            }
            handshake_done_ = true;

            // 保存握手后的剩余数据到 first_packet_
            if (consumed < total) {
                first_packet_.assign(buf + consumed, buf + total);
                first_packet_offset_ = 0;
            }

            co_return HandshakeResult{req, HandshakeFailReason::NONE};
        }

        // 数据太长但仍无法解析，可能是非 Trojan 流量
        if (total > 1024) {
            inner_->ClearPhaseDeadline();
            LOG_ACCESS_DEBUG("[{}] Invalid protocol from {}: data too long", tag, client_ip);
            co_return HandshakeResult{std::nullopt, HandshakeFailReason::INVALID_PROTOCOL};
        }
    }

    inner_->ClearPhaseDeadline();
    co_return HandshakeResult{std::nullopt, HandshakeFailReason::INVALID_PROTOCOL};
}

cobalt::task<std::size_t> TrojanServerStream::AsyncRead(net::mutable_buffer buf) {
    // 先返回首包数据
    if (first_packet_offset_ < first_packet_.size()) {
        size_t to_copy = std::min(buf.size(),
                                   first_packet_.size() - first_packet_offset_);
        std::memcpy(buf.data(),
                    first_packet_.data() + first_packet_offset_,
                    to_copy);
        first_packet_offset_ += to_copy;

        if (first_packet_offset_ >= first_packet_.size()) {
            first_packet_.clear();
            first_packet_.shrink_to_fit();
            first_packet_offset_ = 0;
        }

        co_return to_copy;
    }

    co_return co_await inner_->AsyncRead(buf);
}

cobalt::task<std::size_t> TrojanServerStream::AsyncWrite(net::const_buffer buf) {
    co_return co_await inner_->AsyncWrite(buf);
}

void TrojanServerStream::ShutdownRead() { inner_->ShutdownRead(); }
void TrojanServerStream::ShutdownWrite() { inner_->ShutdownWrite(); }

cobalt::task<void> TrojanServerStream::AsyncShutdownWrite() {
    co_await inner_->AsyncShutdownWrite();
}

void TrojanServerStream::Close() { inner_->Close(); }
void TrojanServerStream::Cancel() noexcept { inner_->Cancel(); }
int TrojanServerStream::NativeHandle() const { return inner_->NativeHandle(); }
net::any_io_executor TrojanServerStream::GetExecutor() const { return inner_->GetExecutor(); }
bool TrojanServerStream::IsOpen() const { return inner_->IsOpen(); }

// ============================================================================
// TrojanClientStream 实现
// ============================================================================

TrojanClientStream::TrojanClientStream(std::unique_ptr<AsyncStream> inner,
                                       const std::string& password,
                                       const TargetAddress& target)
    : inner_(std::move(inner))
    , password_(password)
    , target_(target) {}

TrojanClientStream::~TrojanClientStream() = default;

cobalt::task<bool> TrojanClientStream::SendRequest() {
    if (request_sent_) {
        co_return true;
    }

    // 立即设置标志，防止并发协程重复进入
    // （relay 中 AsyncRead 和 AsyncWrite 通过 cobalt::gather 并发执行）
    request_sent_ = true;

    std::array<uint8_t, 512> request_buf{};
    size_t request_len = TrojanCodec::EncodeRequestTo(
        password_, TrojanCommand::CONNECT, target_,
        request_buf.data(), request_buf.size());
    if (request_len == 0) {
        co_return false;
    }

    try {
        size_t written = 0;
        while (written < request_len) {
            size_t n = co_await inner_->AsyncWrite(
                net::buffer(request_buf.data() + written, request_len - written));
            if (n == 0) {
                co_return false;
            }
            written += n;
        }
        co_return true;
    } catch (...) {
        co_return false;
    }
}

cobalt::task<std::size_t> TrojanClientStream::AsyncRead(net::mutable_buffer buf) {
    if (!request_sent_) {
        if (!co_await SendRequest()) {
            co_return 0;
        }
    }
    co_return co_await inner_->AsyncRead(buf);
}

cobalt::task<std::size_t> TrojanClientStream::AsyncWrite(net::const_buffer buf) {
    if (!request_sent_) {
        // 立即设置标志，防止并发协程重复进入
        request_sent_ = true;

        std::array<uint8_t, 512> header{};
        size_t header_len = TrojanCodec::EncodeRequestTo(
            password_,
            TrojanCommand::CONNECT,
            target_,
            header.data(),
            header.size());
        if (header_len == 0) {
            co_return 0;
        }

        try {
            // 合并 header + payload 为单次写入，避免 2 个 TCP 包
            const size_t payload_len = buf.size();
            const size_t total_len = header_len + payload_len;
            std::vector<uint8_t> combined(total_len);
            std::memcpy(combined.data(), header.data(), header_len);
            if (payload_len > 0) {
                std::memcpy(combined.data() + header_len, buf.data(), payload_len);
            }

            size_t written = 0;
            while (written < total_len) {
                size_t n = co_await inner_->AsyncWrite(
                    net::buffer(combined.data() + written, total_len - written));
                if (n == 0) {
                    co_return 0;
                }
                written += n;
            }
            co_return payload_len;
        } catch (...) {
            co_return 0;
        }
    }

    co_return co_await inner_->AsyncWrite(buf);
}

void TrojanClientStream::ShutdownRead() { inner_->ShutdownRead(); }
void TrojanClientStream::ShutdownWrite() { inner_->ShutdownWrite(); }

cobalt::task<void> TrojanClientStream::AsyncShutdownWrite() {
    co_await inner_->AsyncShutdownWrite();
}

void TrojanClientStream::Close() { inner_->Close(); }
void TrojanClientStream::Cancel() noexcept { inner_->Cancel(); }
int TrojanClientStream::NativeHandle() const { return inner_->NativeHandle(); }
net::any_io_executor TrojanClientStream::GetExecutor() const { return inner_->GetExecutor(); }
bool TrojanClientStream::IsOpen() const { return inner_->IsOpen(); }

}  // namespace acpp::trojan
