#pragma once

#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "proxy/expiring_keyed_map.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

class GroupCoordinator;

namespace ss {

enum class Ss2022SaltAdmission : uint8_t { Accepted, Replayed, Limited };

// Sans-I/O state, exclusively owned by the process-wide coordinator. Length is
// part of the complete salt key; neither inbound tag nor user partitions it.
class Ss2022SaltPool {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr size_t kMaxSalts = size_t{1} << 18;
    static constexpr auto kRetention = std::chrono::seconds(65);

    explicit Ss2022SaltPool(size_t capacity = kMaxSalts) : entries_(capacity), capacity_(capacity) {}
    Ss2022SaltPool(const Ss2022SaltPool&) = delete;
    Ss2022SaltPool& operator=(const Ss2022SaltPool&) = delete;

    // Check duplicates before capacity. Never evict an unexpired entry, including
    // on allocation failure. Only authenticated, timestamp-checked TCP requests
    // may reach this operation; outbound salts are never inserted.
    [[nodiscard]] Ss2022SaltAdmission Admit(
        std::span<const uint8_t> salt, Clock::time_point now) noexcept;
    [[nodiscard]] size_t Size() const noexcept { return entries_.size(); }

private:
    proxy::ExpiringKeyedMap<33, std::monostate, Clock::time_point> entries_;
    size_t capacity_;
};

// One bounded control round trip. Mailbox/allocation exhaustion returns Limited;
// closed admission throws IoSystemError(operation_aborted). An accepted operation
// completes on its owner before the caller resumes, including cancellation.
[[nodiscard]] net::awaitable<Ss2022SaltAdmission> AdmitSs2022RequestSalt(
    GroupCoordinator& coordinator, const KeyBytes& salt);

}  // namespace ss
