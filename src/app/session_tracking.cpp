#include "acppnode/app/session_tracking.hpp"

#include "acppnode/common/session.hpp"

namespace acpp::app {

SessionTrackingState::SessionTrackingState() = default;
SessionTrackingState::~SessionTrackingState() = default;
SessionTrackingState::SessionTrackingState(SessionTrackingState&&) noexcept = default;
SessionTrackingState& SessionTrackingState::operator=(SessionTrackingState&&) noexcept = default;

void SessionTrackingState::RegisterActiveSession(
    ActiveSession& node,
    std::string_view accounting_key,
    int64_t user_id,
    session::Traffic& traffic) {
    if (accounting_key.empty() || user_id <= 0 || node.linked) return;
    auto entry = accounts_.find(accounting_key);
    const bool inserted = entry == accounts_.end();
    if (inserted) {
        entry = accounts_.try_emplace(memory::ThreadLocalString{accounting_key}).first;
    }
    AccountBucket& bucket = entry->second;
    try {
        auto& account = bucket.traffic.try_emplace(user_id).first->second;
        node.account = &account;
        ++account.active;
    } catch (...) {
        if (inserted) accounts_.erase(entry);
        throw;
    }
    node.bucket = &bucket;
    node.user_id = user_id;
    node.traffic = &traffic;
    node.last_reported_up = 0;
    node.last_reported_down = 0;
    node.prev = nullptr;
    node.next = bucket.active_head;
    if (node.next) node.next->prev = &node;
    bucket.active_head = &node;
    node.linked = true;
}

void SessionTrackingState::UnregisterActiveSession(ActiveSession& node) noexcept {
    if (!node.linked) return;
    if (node.prev) node.prev->next = node.next;
    else node.bucket->active_head = node.next;
    if (node.next) node.next->prev = node.prev;
    auto& account = *node.account;
    account.completed.upload += node.traffic->bytes_up - node.last_reported_up;
    account.completed.download += node.traffic->bytes_down - node.last_reported_down;
    --account.active;
    node = {};
}

UserTrafficSnapshot SessionTrackingState::CollectAndResetTraffic(std::string_view accounting_key) {
    UserTrafficSnapshot result;
    const auto entry = accounts_.find(accounting_key);
    if (entry == accounts_.end()) return result;

    AccountBucket& bucket = entry->second;
    for (auto* node = bucket.active_head; node; node = node->next) {
        const auto up = node->traffic->bytes_up - node->last_reported_up;
        const auto down = node->traffic->bytes_down - node->last_reported_down;
        node->last_reported_up = node->traffic->bytes_up;
        node->last_reported_down = node->traffic->bytes_down;
        node->account->completed.upload += up;
        node->account->completed.download += down;
    }

    result.users.reserve(bucket.traffic.size());
    for (const auto& [user_id, account] : bucket.traffic) {
        if (account.completed.upload || account.completed.download) {
            result.users.emplace(user_id, account.completed);
        }
    }

    for (auto it = bucket.traffic.begin(); it != bucket.traffic.end();) {
        if (it->second.active == 0) {
            it = bucket.traffic.erase(it);
        } else {
            it->second.completed = {};
            ++it;
        }
    }
    if (bucket.traffic.empty()) {
        accounts_.erase(entry);
    }
    return result;
}

}  // namespace acpp::app
