#pragma once

// ============================================================================
// base_inbound.hpp - Inbound 协议的公共基类
//
// 统一 VMess/Trojan 等 Inbound 协议的公共部分：
// - 配置结构
// - AcceptLoop 逻辑
// - TLS 握手
// - 连接限制检查
// - PROXY Protocol 解析
// ============================================================================

#include "acppnode/protocol/sniff_config.hpp"
#include "acppnode/transport/proxy_protocol.hpp"
#include "acppnode/transport/tcp_stream.hpp"   // SetupListenerSocket
#include "acppnode/transport/tls_stream.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/connection_guard.hpp"
#include "acppnode/infra/log.hpp"

#include <boost/asio/detached.hpp>

namespace acpp {

// ============================================================================
// 公共 Inbound 配置基类
// ============================================================================
struct BaseInboundConfig {
    std::string tag;                // 入站标识
    std::string listen = std::string(constants::network::kAnyIpv4); // 监听地址
    uint16_t port = 0;              // 监听端口
    uint32_t worker_id = 0;         // 所属 worker
    
    // TLS 配置
    bool tls_enable = false;        // 是否启用 TLS
    TlsConfig tls;                  // TLS 配置（cert/key 为空则自签名）
    
    // Sniff 配置
    SniffConfig sniff;
    
    virtual ~BaseInboundConfig() noexcept = default;
};

// ============================================================================
// BaseInbound - Inbound 公共基类
//
// 提供:
// - TLS 上下文创建
// - 连接限制检查
// - PROXY Protocol 检测
//
// 注意：Accept 循环由各 Worker 的 AcceptLoop（SO_REUSEPORT）管理，
//       Inbound 只负责协议处理。
// ============================================================================
template<typename DerivedConfig>
class BaseInbound : public IInbound {
public:
    BaseInbound(net::any_io_executor executor,
                const DerivedConfig& config,
                StatsShard& stats,
                ConnectionLimiterPtr limiter,
                InboundHandler handler)
        : executor_(executor)
        , config_(config)
        , stats_(stats)
        , limiter_(std::move(limiter))
        , handler_(std::move(handler)) {}

    ~BaseInbound() noexcept override {
        Stop();
    }

    bool Start() override {
        if (running_) {
            return true;
        }

        // 创建 TLS 上下文（如果需要）
        if (config_.tls_enable) {
            ssl_ctx_ = CreateSslContext();
            if (!ssl_ctx_) {
                LOG_ERROR("[{}] Failed to create SSL context", config_.tag);
                return false;
            }
        }

        running_ = true;
        return true;
    }

    void Stop() override {
        running_ = false;
    }

    std::string Tag() const override { return config_.tag; }
    std::string ListenAddr() const override { return config_.listen; }
    uint16_t ListenPort() const override { return config_.port; }

    // 接收 Dispatcher 推送的连接
    cobalt::task<void> HandlePushedConnection(tcp::socket socket) override {
        co_await HandleConnection(std::move(socket));
    }

    // 设置认证回调
    void SetAuthCallback(std::function<void(const std::string&)> cb) override {
        auth_callback_ = std::move(cb);
    }

    // 获取连接限制器
    ConnectionLimiter& Limiter() { return *limiter_; }
    const ConnectionLimiter& Limiter() const { return *limiter_; }

protected:
    // 子类实现的虚函数
    virtual cobalt::task<void> HandleConnection(tcp::socket socket) = 0;

    // 创建 SSL 上下文（子类可重写以定制）
    virtual std::unique_ptr<SslContext> CreateSslContext() {
        if (!config_.tls.cert_file.empty() && !config_.tls.key_file.empty()) {
            auto ctx = SslContext::CreateServer(config_.tls);
            if (ctx) {
                LOG_DEBUG("[{}] Using TLS certificate: {}", config_.tag, config_.tls.cert_file);
            }
            return ctx;
        } else {
            auto ctx = SslContext::CreateServerAutoSign(config_.tls);
            if (ctx) {
                LOG_DEBUG("[{}] TLS 自动签名模式（按 SNI 生成证书）", config_.tag);
            }
            return ctx;
        }
    }

    // 检测并解析 PROXY Protocol（返回消费后剩余的数据）
    cobalt::task<std::tuple<std::string, uint16_t, std::vector<uint8_t>>>
    DetectProxyProtocol(tcp::socket& socket, const std::string& client_ip) {
        std::string real_ip = client_ip;
        uint16_t real_port = 0;
        std::vector<uint8_t> pending_data;

        std::vector<uint8_t> buffer(256);

        auto [ec, n] = co_await socket.async_read_some(
            net::buffer(buffer),
            net::as_tuple(cobalt::use_op));

        if (ec || n == 0) {
            co_return std::make_tuple(real_ip, real_port, pending_data);
        }

        auto result = ProxyProtocolParser::Parse(buffer.data(), n);

        if (result.success() && !result.src_ip.empty()) {
            real_ip = result.src_ip;
            real_port = result.src_port;
            LOG_ACCESS_DEBUG("[{}] PROXY protocol detected: {} -> real IP {}",
                      config_.tag, client_ip, real_ip);

            if (result.consumed < n) {
                pending_data.assign(
                    buffer.begin() + result.consumed,
                    buffer.begin() + n);
            }
        } else {
            // 不是 PROXY Protocol，所有数据都是 pending
            pending_data.assign(buffer.begin(), buffer.begin() + n);
        }

        co_return std::make_tuple(real_ip, real_port, std::move(pending_data));
    }

    // 公共成员
    net::any_io_executor executor_;
    DerivedConfig config_;
    StatsShard& stats_;
    ConnectionLimiterPtr limiter_;
    InboundHandler handler_;

    std::unique_ptr<SslContext> ssl_ctx_;
    std::function<void(const std::string&)> auth_callback_;  // 认证成功回调
    bool running_ = false;
};

}  // namespace acpp
