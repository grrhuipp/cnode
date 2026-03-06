#pragma once

// ============================================================================
// DelegatingAsyncStream — 装饰器流的公共基类
//
// 持有一个 inner_ 流，并将所有 AsyncStream 虚函数转发给它。
// 子类（如 SsServerAsyncStream、VMessServerAsyncStream）只需覆写真正有
// 差异的方法（通常是 AsyncRead / AsyncWrite），其余转发由此基类统一提供。
//
// 使用方式：
//   class MyEncryptedStream final : public DelegatingAsyncStream {
//   public:
//       explicit MyEncryptedStream(std::unique_ptr<AsyncStream> inner)
//           : DelegatingAsyncStream(std::move(inner)) {}
//
//       cobalt::task<size_t> AsyncRead(net::mutable_buffer buf) override;
//       cobalt::task<size_t> AsyncWrite(net::const_buffer buf) override;
//   };
// ============================================================================

#include "acppnode/transport/async_stream.hpp"
#include <memory>

namespace acpp {

class DelegatingAsyncStream : public AsyncStream {
public:
    explicit DelegatingAsyncStream(std::unique_ptr<AsyncStream> inner) noexcept
        : inner_(std::move(inner)) {}

    ~DelegatingAsyncStream() noexcept override = default;

    DelegatingAsyncStream(const DelegatingAsyncStream&)            = delete;
    DelegatingAsyncStream& operator=(const DelegatingAsyncStream&) = delete;

    // ── 数据传输 ─────────────────────────────────────────────────────────────

    cobalt::task<size_t> AsyncRead(net::mutable_buffer buf) override {
        return inner_->AsyncRead(buf);
    }

    cobalt::task<size_t> AsyncWrite(net::const_buffer buf) override {
        return inner_->AsyncWrite(buf);
    }

    // 注意：不覆写 ReadMultiBuffer / WriteMultiBuffer，
    // 让基类 AsyncStream 的实现通过虚函数调用 this->AsyncRead/AsyncWrite，
    // 确保派生类（如 VMessServerAsyncStream、SsServerAsyncStream）
    // 的加解密逻辑不被绕过。

    // ── 关闭操作 ─────────────────────────────────────────────────────────────

    void ShutdownRead() override                { inner_->ShutdownRead(); }
    void ShutdownWrite() override               { inner_->ShutdownWrite(); }
    cobalt::task<void> AsyncShutdownWrite() override {
        return inner_->AsyncShutdownWrite();
    }
    void Cancel() noexcept override             { inner_->Cancel(); }
    void Close() override                       { inner_->Close(); }

    // ── 状态查询 ─────────────────────────────────────────────────────────────

    int NativeHandle() const override           { return inner_->NativeHandle(); }
    net::any_io_executor GetExecutor() const override { return inner_->GetExecutor(); }
    bool IsOpen() const override                { return inner_->IsOpen(); }

    // ── 底层 TcpStream 访问（透传装饰器链）─────────────────────────────────

    TcpStream* GetBaseTcpStream() override { return inner_->GetBaseTcpStream(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_->GetBaseTcpStream(); }

protected:
    std::unique_ptr<AsyncStream> inner_;
};

}  // namespace acpp
