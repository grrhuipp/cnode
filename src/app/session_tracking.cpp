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
        memory::ThreadLocalString,
        UserTrafficMap,
        TransparentStringHash,
        TransparentStringEq>;

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
        it = store.try_emplace(memory::ThreadLocalString(tag)).first;
    }
    auto& traffic = it->second[user_id];
    traffic.upload += upload;
    traffic.download += download;
}

}  // namespace

struct SessionTrackingState::Impl {
    LocalTrafficStore local_traffic;
    ActiveSession* active_head = nullptr;
};

SessionTrackingState::SessionTrackingState()
    : impl_(std::make_unique<Impl>()) {}

SessionTrackingState::~SessionTrackingState() = default;
SessionTrackingState::SessionTrackingState(SessionTrackingState&&) noexcept = default;
SessionTrackingState& SessionTrackingState::operator=(SessionTrackingState&&) noexcept = default;

void SessionTrackingState::RegisterActiveSession(ActiveSession& node,
                                                 std::string_view tag,
                                                 int64_t user_id,
                                                 session::Traffic& traffic) noexcept {
    if (user_id <= 0 || node.linked) {
        return;
    }

    node.tag = tag;
    node.user_id = user_id;
    node.traffic = &traffic;
    node.last_reported_up = 0;
    node.last_reported_down = 0;
    node.prev = nullptr;
    node.next = impl_->active_head;
    if (impl_->active_head) {
        impl_->active_head->prev = &node;
    }
    impl_->active_head = &node;
    node.linked = true;
}

void SessionTrackingState::UnregisterActiveSession(ActiveSession& node) noexcept {
    if (!node.linked) {
        return;
    }

    if (node.prev) {
        node.prev->next = node.next;
    } else {
        impl_->active_head = node.next;
    }
    if (node.next) {
        node.next->prev = node.prev;
    }
    node.prev = nullptr;
    node.next = nullptr;
    node.linked = false;

    if (!node.traffic || node.user_id <= 0) {
        return;
    }
    const uint64_t remaining_up =
        node.traffic->bytes_up > node.last_reported_up
            ? node.traffic->bytes_up - node.last_reported_up
            : 0;
    const uint64_t remaining_down =
        node.traffic->bytes_down > node.last_reported_down
            ? node.traffic->bytes_down - node.last_reported_down
            : 0;
    if (remaining_up > 0 || remaining_down > 0) {
        try {
            AddUserTrafficTo(impl_->local_traffic,
                             node.tag,
                             node.user_id,
                             remaining_up,
                             remaining_down);
        } catch (...) {
        }
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

    for (ActiveSession* session = impl_->active_head; session != nullptr; session = session->next) {
        if (session->tag != tag) {
            continue;
        }
        if (session->user_id <= 0 || !session->traffic) {
            continue;
        }

        const uint64_t cur_up = session->traffic->bytes_up;
        const uint64_t cur_down = session->traffic->bytes_down;
        const uint64_t delta_up = cur_up - session->last_reported_up;
        const uint64_t delta_down = cur_down - session->last_reported_down;
        session->last_reported_up = cur_up;
        session->last_reported_down = cur_down;

        if (delta_up > 0 || delta_down > 0) {
            auto& traffic = result.users[session->user_id];
            traffic.upload += delta_up;
            traffic.download += delta_down;
        }
    }

    return result;
}
}  // namespace acpp::app
