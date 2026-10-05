#include "acppnode/app/session_tracking.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/runtime/channel.hpp"
#include "acppnode/common/string_hash.hpp"

#include <asio/strand.hpp>

#include <string>
#include <vector>

namespace acpp::app {
namespace {
using UserTrafficMap = memory::DataUnorderedMap<int64_t, UserTraffic>;
using TrafficStore = memory::DataUnorderedMap<std::string, UserTrafficMap,
    TransparentStringHash, TransparentStringEq>;

struct ActiveSession {
    std::string tag;
    int64_t user_id = 0;
    std::shared_ptr<session::TrafficSource> source;
    uint64_t last_reported_up = 0;
    uint64_t last_reported_down = 0;
};
using ActiveSessionMap = memory::DataUnorderedMap<uint64_t, ActiveSession>;

void AddTraffic(TrafficStore& store, std::string_view tag, int64_t user_id,
                uint64_t upload, uint64_t download) {
    if (user_id <= 0 || (upload == 0 && download == 0)) return;
    auto it = store.find(tag);
    if (it == store.end()) it = store.try_emplace(std::string(tag)).first;
    auto& value = it->second[user_id];
    value.upload += upload;
    value.download += download;
}
}

struct SessionTrackingState::Impl {
    explicit Impl(net::any_io_executor executor)
        : channel(net::make_strand(std::move(executor)), 65536) {}
    ServiceChannel channel;
    TrafficStore traffic;
    ActiveSessionMap active;
    // Collection can suspend while reading a connection snapshot. The
    // reservation is an ordinary service-state check, not a coroutine mutex.
    bool collecting = false;
};

SessionTrackingState::SessionTrackingState(net::any_io_executor executor)
    : impl_(std::make_unique<Impl>(std::move(executor))) {}
SessionTrackingState::~SessionTrackingState() = default;

net::awaitable<void> SessionTrackingState::AddUserTraffic(std::string tag,
    int64_t user_id, uint64_t upload, uint64_t download) {
    return impl_->channel.Call([this, tag = std::move(tag), user_id, upload, download] {
        AddTraffic(impl_->traffic, tag, user_id, upload, download);
    });
}

net::awaitable<SessionTrackingState::Registration> SessionTrackingState::RegisterActiveSession(uint64_t conn_id,
    std::string tag, int64_t user_id, std::shared_ptr<session::TrafficSource> source) {
    auto reservation = impl_->channel.TryReserve();
    if (!reservation) throw ServiceChannelFull();
    co_await impl_->channel.CallReserved(reservation,
        [this, conn_id, tag = std::move(tag), user_id, source = std::move(source)]() mutable {
            if (user_id <= 0) return;
            if (!source) throw std::invalid_argument("active session needs a traffic source");
            if (!impl_->active.try_emplace(conn_id, ActiveSession{
                    .tag = std::move(tag), .user_id = user_id, .source = std::move(source)}).second)
                throw std::logic_error("duplicate active session");
        });
    co_return Registration{.reservation = std::move(reservation), .conn_id = conn_id};
}

net::awaitable<void> SessionTrackingState::UnregisterActiveSession(
    Registration registration, session::Traffic traffic) {
    co_await impl_->channel.CallReserved(registration.reservation,
        [this, conn_id = registration.conn_id, traffic] {
            auto it = impl_->active.find(conn_id);
            if (it == impl_->active.end()) return;
            const auto& active = it->second;
            AddTraffic(impl_->traffic, active.tag, active.user_id,
                traffic.bytes_up - active.last_reported_up,
                traffic.bytes_down - active.last_reported_down);
            impl_->active.erase(it);
            MaybeShrinkHashContainer(impl_->active, 256);
        });
}

net::awaitable<UserTrafficSnapshot> SessionTrackingState::CollectAndResetTraffic(std::string tag) {
    // Post owns the collection coroutine and keeps it on the service strand;
    // every snapshot source is an owning bounded endpoint on its connection.
    auto collect = [this](std::string owned_tag) -> net::awaitable<UserTrafficSnapshot> {
        if (impl_->collecting) throw ServiceChannelFull();
        impl_->collecting = true;
        struct Reset {
            bool& state;
            ~Reset() { state = false; }
        } reset{impl_->collecting};
        struct Pending { uint64_t id; std::shared_ptr<session::TrafficSource> source; };
        std::vector<Pending> pending;
        for (const auto& [id, active] : impl_->active)
            if (active.tag == owned_tag) pending.push_back({id, active.source});
        for (const auto& item : pending) {
            const auto snapshot = co_await item.source->Snapshot();
            const auto it = impl_->active.find(item.id);
            if (it == impl_->active.end() || it->second.source != item.source) continue;
            auto& active = it->second;
            AddTraffic(impl_->traffic, active.tag, active.user_id,
                snapshot.bytes_up - active.last_reported_up,
                snapshot.bytes_down - active.last_reported_down);
            active.last_reported_up = snapshot.bytes_up;
            active.last_reported_down = snapshot.bytes_down;
        }
        UserTrafficSnapshot result;
        const auto it = impl_->traffic.find(owned_tag);
        if (it != impl_->traffic.end()) {
            result.users.reserve(it->second.size());
            for (const auto& [uid, traffic] : it->second) result.users.emplace(uid, traffic);
            it->second.clear();
            MaybeShrinkHashContainer(it->second, 64);
        }
        co_return result;
    };
    co_return co_await impl_->channel.Post(collect(std::move(tag)));
}

}  // namespace acpp::app
