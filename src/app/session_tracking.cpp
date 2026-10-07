#include "acppnode/app/session_tracking.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/string_hash.hpp"

#include <string>

namespace acpp::app {

namespace {

using UserTrafficMap = memory::ThreadLocalUnorderedMap<int64_t, UserTraffic>;

using LocalTrafficStore =
    memory::ThreadLocalUnorderedMap<
        std::string,
        UserTrafficMap,
        TransparentStringHash,
        TransparentStringEq>;

struct ActiveSession {
    memory::ThreadLocalString tag;
    int64_t user_id = 0;
    session::Traffic* traffic = nullptr;
    uint64_t last_reported_up = 0;
    uint64_t last_reported_down = 0;
};

using ActiveSessionMap =
    memory::ThreadLocalUnorderedMap<uint64_t, ActiveSession>;

void AddUserTrafficTo(LocalTrafficStore& store,
                      std::string_view tag,
                      int64_t user_id,
                      uint64_t upload,
                      uint64_t download) {
    if (user_id <= 0) {
        return;
    }
    auto it = store.find(tag);
    if (it == store.end()) {
        it = store.try_emplace(std::string(tag)).first;
    }
    auto& traffic = it->second[user_id];
    traffic.upload += upload;
    traffic.download += download;
}

}  // namespace

struct SessionTrackingState::Impl {
    LocalTrafficStore local_traffic;
    ActiveSessionMap active_sessions;
};

SessionTrackingState::SessionTrackingState()
    : impl_(std::make_unique<Impl>()) {}

SessionTrackingState::~SessionTrackingState() = default;
SessionTrackingState::SessionTrackingState(SessionTrackingState&&) noexcept = default;
SessionTrackingState& SessionTrackingState::operator=(SessionTrackingState&&) noexcept = default;

void SessionTrackingState::AddUserTraffic(std::string_view tag,
                                          int64_t user_id,
                                          uint64_t upload,
                                          uint64_t download) {
    AddUserTrafficTo(impl_->local_traffic, tag, user_id, upload, download);
}

void SessionTrackingState::RegisterActiveSession(uint64_t conn_id,
                                                 std::string_view tag,
                                                 int64_t user_id,
                                                 session::Traffic& traffic) {
    if (user_id <= 0) {
        return;
    }

    impl_->active_sessions[conn_id] = ActiveSession{
        .tag = memory::ThreadLocalString(tag),
        .user_id = user_id,
        .traffic = &traffic,
    };
}

void SessionTrackingState::UnregisterActiveSession(uint64_t conn_id,
                                                   const session::Traffic& traffic) noexcept {
    memory::ThreadLocalString tag;
    int64_t user_id = 0;
    uint64_t last_up = 0;
    uint64_t last_down = 0;
    if (auto it = impl_->active_sessions.find(conn_id); it != impl_->active_sessions.end()) {
        tag = std::move(it->second.tag);
        user_id = it->second.user_id;
        last_up = it->second.last_reported_up;
        last_down = it->second.last_reported_down;
        impl_->active_sessions.erase(it);
        MaybeShrinkHashContainer(impl_->active_sessions, 256);
    } else {
        return;
    }

    const uint64_t remaining_up =
        traffic.bytes_up > last_up ? traffic.bytes_up - last_up : 0;
    const uint64_t remaining_down =
        traffic.bytes_down > last_down ? traffic.bytes_down - last_down : 0;
    if (remaining_up > 0 || remaining_down > 0) {
        AddUserTrafficTo(impl_->local_traffic,
                         std::string_view(tag),
                         user_id,
                         remaining_up,
                         remaining_down);
    }
}

UserTrafficSnapshot
SessionTrackingState::CollectAndResetTraffic(std::string_view tag) {
    UserTrafficSnapshot result;

    if (auto it = impl_->local_traffic.find(tag); it != impl_->local_traffic.end()) {
        result.users.reserve(it->second.size());
        for (auto& [user_id, traffic] : it->second) {
            result.users.emplace(user_id, std::move(traffic));
        }
        it->second.clear();
        MaybeShrinkHashContainer(it->second, 64);
    }

    for (auto& [conn_id, session] : impl_->active_sessions) {
        (void)conn_id;
        if (std::string_view(session.tag) != tag) {
            continue;
        }
        if (session.user_id <= 0 || !session.traffic) {
            continue;
        }

        const uint64_t cur_up = session.traffic->bytes_up;
        const uint64_t cur_down = session.traffic->bytes_down;
        const uint64_t delta_up = cur_up - session.last_reported_up;
        const uint64_t delta_down = cur_down - session.last_reported_down;
        session.last_reported_up = cur_up;
        session.last_reported_down = cur_down;

        if (delta_up > 0 || delta_down > 0) {
            auto& traffic = result.users[session.user_id];
            traffic.upload += delta_up;
            traffic.download += delta_down;
        }
    }

    return result;
}

}  // namespace acpp::app
