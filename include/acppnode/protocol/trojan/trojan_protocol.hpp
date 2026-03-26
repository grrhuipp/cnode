#pragma once

// ============================================================================
// trojan_protocol.hpp - Trojan 协议伞形头
//
// 包含所有 Trojan 子模块：
// - trojan_user_manager.hpp  用户管理（TrojanUserInfo, TrojanUserManager）
// - trojan_codec.hpp         协议编解码（TrojanCodec, TrojanRequest 等）
// - TrojanServerStream       服务端协议流
// - TrojanClientStream       客户端协议流
// ============================================================================

#include "acppnode/protocol/trojan/trojan_user_manager.hpp"
#include "acppnode/protocol/trojan/trojan_codec.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/session_context.hpp"

namespace acpp::trojan {

// ============================================================================
// Trojan 服务端流
// ============================================================================
class TrojanServerStream final : public AsyncStream {
public:
    // 从已完成 TLS 握手的流构造
    TrojanServerStream(std::unique_ptr<AsyncStream> inner,
                       TrojanUserManager& user_manager);

    ~TrojanServerStream() override;

    // 禁止拷贝
    TrojanServerStream(const TrojanServerStream&) = delete;
    TrojanServerStream& operator=(const TrojanServerStream&) = delete;

    // 执行 Trojan 握手
    // 返回 HandshakeResult，包含请求和失败原因
    // tag: 入站标识，用于日志输出
    // client_ip: 客户端 IP，用于日志输出
    cobalt::task<HandshakeResult> DoHandshake(const std::string& tag, const std::string& client_ip);

    // 获取用户信息（握手成功后有效）
    const std::string& UserEmail() const { return user_info_.email; }
    int64_t UserId() const { return user_info_.user_id; }
    uint64_t SpeedLimit() const { return user_info_.speed_limit; }
    const TrojanUserInfo& UserInfo() const { return user_info_; }

    // AsyncStream 接口实现
    cobalt::task<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    cobalt::task<std::size_t> AsyncWrite(net::const_buffer buf) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    cobalt::task<void> AsyncShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    net::any_io_executor GetExecutor() const override;
    bool IsOpen() const override;

    TcpStream* GetBaseTcpStream() override { return inner_->GetBaseTcpStream(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_->GetBaseTcpStream(); }

private:
    std::unique_ptr<AsyncStream> inner_;
    TrojanUserManager& user_manager_;
    TrojanUserInfo user_info_;

    // 首包数据（握手解析后的剩余数据）
    memory::ByteVector first_packet_;
    size_t first_packet_offset_ = 0;

    bool handshake_done_ = false;
};

// ============================================================================
// Trojan 客户端流
// ============================================================================
class TrojanClientStream final : public AsyncStream {
public:
    // 从已完成 TLS 握手的流构造
    TrojanClientStream(std::unique_ptr<AsyncStream> inner,
                       const std::string& password,
                       const TargetAddress& target);

    ~TrojanClientStream() override;

    // 禁止拷贝
    TrojanClientStream(const TrojanClientStream&) = delete;
    TrojanClientStream& operator=(const TrojanClientStream&) = delete;

    // AsyncStream 接口实现
    cobalt::task<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    cobalt::task<std::size_t> AsyncWrite(net::const_buffer buf) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    cobalt::task<void> AsyncShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    net::any_io_executor GetExecutor() const override;
    bool IsOpen() const override;

    TcpStream* GetBaseTcpStream() override { return inner_->GetBaseTcpStream(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_->GetBaseTcpStream(); }

private:
    // 发送 Trojan 请求头
    cobalt::task<bool> SendRequest();

    std::unique_ptr<AsyncStream> inner_;
    std::string password_;
    TargetAddress target_;
    bool request_sent_ = false;
};

}  // namespace acpp::trojan
