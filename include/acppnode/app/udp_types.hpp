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
// PacketCallback - UDP 回包热路径的小对象回调
//
// 只支持 move-only；常见 relay/mux/SS UDP 回包 lambda 直接放在对象内，
// 注册回调时不经过 std::function 的 type-erasure 堆节点。
// ============================================================================
class PacketCallback {
public:
    static constexpr size_t kInlineBytes = 176;

    PacketCallback() noexcept = default;
    PacketCallback(std::nullptr_t) noexcept {}

    PacketCallback(const PacketCallback&) = delete;
    PacketCallback& operator=(const PacketCallback&) = delete;

    PacketCallback(PacketCallback&& other) noexcept {
        MoveFrom(std::move(other));
    }

    PacketCallback& operator=(PacketCallback&& other) noexcept {
        if (this != &other) {
            Reset();
            MoveFrom(std::move(other));
        }
        return *this;
    }

    template <typename Fn>
        requires (!std::is_same_v<std::decay_t<Fn>, PacketCallback> &&
                  std::is_invocable_v<std::decay_t<Fn>&, UDPPacketView>)
    PacketCallback(Fn&& fn) {
        using F = std::decay_t<Fn>;
        static_assert(sizeof(F) <= kInlineBytes,
                      "UDP PacketCallback capture is too large for inline hot-path storage");
        static_assert(alignof(F) <= alignof(std::max_align_t),
                      "UDP PacketCallback capture alignment is too large");

        new (storage_) F(std::forward<Fn>(fn));
        invoke_ = [](void* ptr, UDPPacketView pkt) {
            (*static_cast<F*>(ptr))(pkt);
        };
        move_ = [](void* dst, void* src) {
            new (dst) F(std::move(*static_cast<F*>(src)));
            static_cast<F*>(src)->~F();
        };
        destroy_ = [](void* ptr) {
            static_cast<F*>(ptr)->~F();
        };
    }

    ~PacketCallback() {
        Reset();
    }

    explicit operator bool() const noexcept {
        return invoke_ != nullptr;
    }

    // 回调异常不能逃出 Worker UDP 接收/回包循环；false 表示空回调或执行失败。
    [[nodiscard]] bool operator()(UDPPacketView pkt) noexcept {
        if (!invoke_) {
            return false;
        }
        try {
            invoke_(storage_, pkt);
            return true;
        } catch (...) {
            return false;
        }
    }

    void Reset() noexcept {
        if (destroy_) {
            destroy_(storage_);
        }
        invoke_ = nullptr;
        move_ = nullptr;
        destroy_ = nullptr;
    }

private:
    void MoveFrom(PacketCallback&& other) noexcept {
        invoke_ = other.invoke_;
        move_ = other.move_;
        destroy_ = other.destroy_;
        if (move_) {
            move_(storage_, other.storage_);
            other.invoke_ = nullptr;
            other.move_ = nullptr;
            other.destroy_ = nullptr;
        }
    }

    alignas(std::max_align_t) std::byte storage_[kInlineBytes]{};
    void (*invoke_)(void*, UDPPacketView) = nullptr;
    void (*move_)(void*, void*) = nullptr;
    void (*destroy_)(void*) = nullptr;
};

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
