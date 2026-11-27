#include "app/stats.hpp"

#include "common/allocator.hpp"
#include "common/session.hpp"

#include <iterator>

namespace app {

SessionTrackingState::SessionTrackingState() = default;
SessionTrackingState::~SessionTrackingState() = default;

void SessionTrackingState::RegisterActiveSession(
    ActiveSession& node,
    std::string_view accounting_key,
    int64_t user_id,
    common::Traffic& traffic) {
    if (accounting_key.empty() || user_id <= 0 || node.bucket) return;
    auto entry = accounts_.find(accounting_key);
    const bool inserted = entry == accounts_.end();
    if (inserted) {
        entry = accounts_.try_emplace(std::string{accounting_key}).first;
        entry->second.key = entry->first;
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
}

void SessionTrackingState::UnregisterActiveSession(ActiveSession& node) noexcept {
    if (!node.bucket) return;
    auto* bucket = node.bucket;
    if (node.prev) node.prev->next = node.next;
    else bucket->active_head = node.next;
    if (node.next) node.next->prev = node.prev;
    auto& account = *node.account;
    account.completed.upload += node.traffic->bytes_up - node.last_reported_up;
    account.completed.download += node.traffic->bytes_down - node.last_reported_down;
    --account.active;
    if (account.active == 0 && account.completed.upload == 0 &&
        account.completed.download == 0) {
        bucket->traffic.erase(node.user_id);
        if (bucket->traffic.empty()) {
            if (const auto entry = accounts_.find(bucket->key); entry != accounts_.end()) {
                accounts_.erase(entry);
                common::MaybeShrinkHashContainer(accounts_, 8);
            }
        } else {
            common::MaybeShrinkHashContainer(bucket->traffic);
        }
    }
    node = {};
}

UserTrafficCounters SessionTrackingState::TakeTraffic(std::string_view accounting_key) {
    UserTrafficCounters result;
    const auto entry = accounts_.find(accounting_key);
    if (entry == accounts_.end()) return result;

    AccountBucket& bucket = entry->second;
    // Folding only moves live bytes into the ledger, so a failed copy below
    // leaves every byte still pending.
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
        it->second.completed = {};
        it = it->second.active == 0 ? bucket.traffic.erase(it) : std::next(it);
    }
    if (bucket.traffic.empty()) {
        accounts_.erase(entry);
        common::MaybeShrinkHashContainer(accounts_, 8);
    } else {
        common::MaybeShrinkHashContainer(bucket.traffic);
    }
    return result;
}

}  // namespace app
