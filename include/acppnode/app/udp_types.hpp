#pragma once

#include "acppnode/common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

namespace acpp {

struct TargetAddress;
class UDPSession;

// UDP receive 回调的只读视图。
// data 指向 UDPSession 的 receive buffer，仅在同步回调期间有效；
// 需要排队或跨协程保存时，回调方应复制到 Buffer/MultiBuffer 局部持有类型。
struct UDPPacketView {
    const TargetAddress& target;
    std::span<const uint8_t> data;
};

// ============================================================================
// InlineUdpCallback - UDP 热路径的小对象回调
//
// 只支持 move-only；常见 relay/mux/SS UDP 回包 lambda 直接放在对象内，
// 注册回调时不经过 std::function 的 type-erasure 堆节点。
// ============================================================================
template <typename... Args>
class InlineUdpCallback {
public:
    static constexpr size_t kInlineBytes = 176;

    InlineUdpCallback() noexcept = default;
    InlineUdpCallback(std::nullptr_t) noexcept {}

    InlineUdpCallback(const InlineUdpCallback&) = delete;
    InlineUdpCallback& operator=(const InlineUdpCallback&) = delete;

    InlineUdpCallback(InlineUdpCallback&& other) noexcept {
        MoveFrom(std::move(other));
    }

    InlineUdpCallback& operator=(InlineUdpCallback&& other) noexcept {
        if (this != &other) {
            Reset();
            MoveFrom(std::move(other));
        }
        return *this;
    }

    template <typename Fn>
        requires (!std::is_same_v<std::decay_t<Fn>, InlineUdpCallback> &&
                  std::is_invocable_v<std::decay_t<Fn>&, Args...>)
    InlineUdpCallback(Fn&& fn) {
        using F = std::decay_t<Fn>;
        static_assert(sizeof(F) <= kInlineBytes,
                      "UDP PacketCallback capture is too large for inline hot-path storage");
        static_assert(alignof(F) <= alignof(std::max_align_t),
                      "UDP PacketCallback capture alignment is too large");

        new (storage_) F(std::forward<Fn>(fn));
        using Result = std::invoke_result_t<F&, Args...>;
        if constexpr (std::is_void_v<Result>) {
            invoke_void_ = [](void* ptr, Args... args) {
                (*static_cast<F*>(ptr))(std::forward<Args>(args)...);
            };
        } else {
            invoke_bool_ = [](void* ptr, Args... args) -> bool {
                return static_cast<bool>(
                    (*static_cast<F*>(ptr))(std::forward<Args>(args)...));
            };
        }
        move_ = [](void* dst, void* src) {
            new (dst) F(std::move(*static_cast<F*>(src)));
            static_cast<F*>(src)->~F();
        };
        destroy_ = [](void* ptr) {
            static_cast<F*>(ptr)->~F();
        };
    }

    ~InlineUdpCallback() {
        Reset();
    }

    explicit operator bool() const noexcept {
        return invoke_void_ != nullptr || invoke_bool_ != nullptr;
    }

    // 回调异常不能逃出 Worker UDP 接收/回包循环；bool 回调的背压结果原样
    // 传播，false 也可表示空回调或执行失败。
    [[nodiscard]] bool operator()(Args... args) noexcept {
        if (!invoke_void_ && !invoke_bool_) {
            return false;
        }
        try {
            if (invoke_bool_) {
                return invoke_bool_(storage_, std::forward<Args>(args)...);
            }
            invoke_void_(storage_, std::forward<Args>(args)...);
            return true;
        } catch (...) {
            return false;
        }
    }

    void Reset() noexcept {
        if (destroy_) {
            destroy_(storage_);
        }
        invoke_void_ = nullptr;
        invoke_bool_ = nullptr;
        move_ = nullptr;
        destroy_ = nullptr;
    }

private:
    void MoveFrom(InlineUdpCallback&& other) noexcept {
        invoke_void_ = other.invoke_void_;
        invoke_bool_ = other.invoke_bool_;
        move_ = other.move_;
        destroy_ = other.destroy_;
        if (move_) {
            move_(storage_, other.storage_);
            other.invoke_void_ = nullptr;
            other.invoke_bool_ = nullptr;
            other.move_ = nullptr;
            other.destroy_ = nullptr;
        }
    }

    alignas(std::max_align_t) std::byte storage_[kInlineBytes]{};
    void (*invoke_void_)(void*, Args...) = nullptr;
    bool (*invoke_bool_)(void*, Args...) = nullptr;
    void (*move_)(void*, void*) = nullptr;
    void (*destroy_)(void*) = nullptr;
};

using PacketCallback = InlineUdpCallback<UDPPacketView>;
using RoutedPacketCallback =
    InlineUdpCallback<UDPPacketView, const udp::endpoint&>;

// datagram 入站与 Mux UDP 子会话通过 transport::Link 进入 dispatcher；
// UDP-capable 出站在自己的 Process 内准备 Worker-local UDP 资源并进入 relay。

// ============================================================================
// UDP Relay 结果
// ============================================================================
struct UDPRelayResult : ResultStatus {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
    bool client_closed_first = false;
};

// ============================================================================
// UDP Relay 配置
// ============================================================================
struct UDPRelayConfig {
    size_t max_packet_size = 65535;          // 最大包大小
    uint64_t speed_limit = 0;               // 限速 (bytes/s), 0 = 不限速
};

}  // namespace acpp
