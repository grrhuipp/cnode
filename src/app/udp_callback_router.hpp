#pragma once

#include "acppnode/app/udp_endpoint_key.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace acpp::detail {

// Worker-local Full Cone callback and reverse-target routing state. Callback
// mutations are deferred while Dispatch is invoking user code, so callback
// objects and routing snapshots remain valid across reentrant unregister/clear.
class UdpCallbackRouter final {
public:
    static constexpr size_t kMaxCallbacks = 1024;
    static constexpr size_t kMaxTargetsPerCallback = 256;
    static constexpr size_t kMaxTargetMappings = 4096;

    struct MappingToken {
        UdpEndpointKey target;
        uint64_t callback_id = 0;
        uint64_t generation = 0;
        bool inserted = false;

        [[nodiscard]] explicit operator bool() const noexcept {
            return callback_id != 0 && generation != 0;
        }
    };

    UdpCallbackRouter();
    ~UdpCallbackRouter() noexcept;

    UdpCallbackRouter(const UdpCallbackRouter&) = delete;
    UdpCallbackRouter& operator=(const UdpCallbackRouter&) = delete;

    [[nodiscard]] uint64_t Register(PacketCallback callback);
    [[nodiscard]] bool Unregister(uint64_t callback_id);

    [[nodiscard]] std::pair<ErrorCode, MappingToken> TrackTarget(
        const UdpEndpointKey& target,
        uint64_t callback_id,
        steady_clock::time_point now);
    void CommitTarget(const MappingToken& token) noexcept;
    void RollbackTarget(const MappingToken& token) noexcept;
    void Prune(steady_clock::time_point now);

    [[nodiscard]] bool Dispatch(
        const UdpEndpointKey& sender,
        UDPPacketView packet,
        steady_clock::time_point now);

    void Clear() noexcept;

    [[nodiscard]] size_t RegisteredCount() const noexcept;
    [[nodiscard]] size_t TargetMappingCount() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::detail
