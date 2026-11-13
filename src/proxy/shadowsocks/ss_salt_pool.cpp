#include "proxy/shadowsocks/ss_salt_pool.hpp"
#include "app/group_coordinator.hpp"

#include <algorithm>
#include <array>
#include <new>

namespace proxy {

static_assert(Ss2022SaltPool::kRetention > std::chrono::seconds(2 * kSs2022MaxTimestampSkew));

Ss2022SaltAdmission Ss2022SaltPool::Admit(
    std::span<const uint8_t> salt, Clock::time_point now) noexcept {
    if (salt.size() != 16 && salt.size() != 32) return Ss2022SaltAdmission::Limited;
    std::array<uint8_t, 33> key{};
    key[0] = static_cast<uint8_t>(salt.size());
    std::copy(salt.begin(), salt.end(), key.begin() + 1);
    entries_.Prune(now);
    if (entries_.Find(key)) return Ss2022SaltAdmission::Replayed;
    if (entries_.size() >= capacity_) return Ss2022SaltAdmission::Limited;
    try {
        return entries_.Insert(key, now + kRetention, std::monostate{})
            ? Ss2022SaltAdmission::Accepted : Ss2022SaltAdmission::Limited;
    } catch (const std::bad_alloc&) {
        return Ss2022SaltAdmission::Limited;
    }
}

namespace {
struct SaltPoolService final : net::execution_context::service {
    inline static net::execution_context::id id;
    explicit SaltPoolService(net::execution_context& context) : service(context) {}
    void shutdown() override {}
    Ss2022SaltPool pool;
};
}  // namespace

net::awaitable<Ss2022SaltAdmission> AdmitSs2022RequestSalt(
    app::GroupCoordinator& coordinator, const KeyBytes& salt) {
    // Copy the small key, not a borrowed worker-side buffer, into owner work.
    try {
        co_return co_await coordinator.PostCall([&coordinator, salt] {
            return net::use_service<SaltPoolService>(coordinator.Services()).pool.Admit(
                salt.span(), Ss2022SaltPool::Clock::now());
        });
    } catch (const app::WorkerMailboxFull&) {
        co_return Ss2022SaltAdmission::Limited;
    } catch (const std::bad_alloc&) {
        co_return Ss2022SaltAdmission::Limited;
    }
}

}  // namespace proxy
