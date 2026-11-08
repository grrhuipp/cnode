#include "app/session_tracking.hpp"

#include "common/session.hpp"
#include "common/container_util.hpp"
#include <stdexcept>

namespace app {

SessionTrackingState::SessionTrackingState() = default;
SessionTrackingState::~SessionTrackingState() = default;

void SessionTrackingState::RegisterActiveSession(
    ActiveSession& node,
    std::string_view accounting_key,
    int64_t user_id,
    session::Traffic& traffic) {
    if (accounting_key.empty() || user_id <= 0 || node.linked) return;
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
    node.linked = true;
}

void SessionTrackingState::UnregisterActiveSession(ActiveSession& node) noexcept {
    if (!node.linked) return;
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
                MaybeShrinkHashContainer(accounts_, 8);
            }
        } else {
            MaybeShrinkHashContainer(bucket->traffic);
        }
    }
    node = {};
}

UserTrafficCounters SessionTrackingState::SnapshotTraffic(std::string_view accounting_key) {
    UserTrafficCounters result;
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
    for (auto& [user_id, account] : bucket.traffic) {
        if (account.completed.upload || account.completed.download) {
            result.users.emplace(user_id, account.completed);
            account.snapshotted = account.completed;
        }
    }
    return result;
}

void SessionTrackingState::CommitTraffic(
    std::string_view accounting_key, const UserTrafficCounters& snapshot) {
    if (snapshot.empty()) return;
    const auto entry = accounts_.find(accounting_key);
    if (entry == accounts_.end()) {
        throw std::logic_error("traffic snapshot account disappeared before commit");
    }
    auto& bucket = entry->second;
    for (const auto& [uid, value] : snapshot) {
        const auto it = bucket.traffic.find(uid);
        if (it == bucket.traffic.end() ||
            it->second.completed.upload < value.upload ||
            it->second.completed.download < value.download ||
            it->second.snapshotted.upload < value.upload ||
            it->second.snapshotted.download < value.download) {
            throw std::logic_error("traffic snapshot exceeds in-flight counters");
        }
    }
    for (const auto& [uid, value] : snapshot) {
        auto it = bucket.traffic.find(uid);
        it->second.completed.upload -= value.upload;
        it->second.completed.download -= value.download;
        it->second.snapshotted.upload -= value.upload;
        it->second.snapshotted.download -= value.download;
        if (it->second.active == 0 && it->second.completed.upload == 0 &&
            it->second.completed.download == 0) {
            bucket.traffic.erase(it);
        }
    }
    if (bucket.traffic.empty()) {
        accounts_.erase(entry);
        MaybeShrinkHashContainer(accounts_, 8);
    } else {
        MaybeShrinkHashContainer(bucket.traffic);
    }
}

void SessionTrackingState::RollbackTraffic(
    std::string_view accounting_key, const UserTrafficCounters& snapshot) {
    if (snapshot.empty()) return;
    const auto entry = accounts_.find(accounting_key);
    if (entry == accounts_.end()) {
        throw std::logic_error("traffic snapshot account disappeared before rollback");
    }
    auto& bucket = entry->second;
    for (const auto& [uid, value] : snapshot) {
        const auto it = bucket.traffic.find(uid);
        if (it == bucket.traffic.end() ||
            it->second.snapshotted.upload < value.upload ||
            it->second.snapshotted.download < value.download) {
            throw std::logic_error("traffic rollback exceeds in-flight counters");
        }
    }
    for (const auto& [uid, value] : snapshot) {
        auto& account = bucket.traffic.find(uid)->second;
        account.snapshotted.upload -= value.upload;
        account.snapshotted.download -= value.download;
    }
}

UserTrafficCounters SessionTrackingState::ExtractAvailableTraffic(
    std::string_view accounting_key) {
    UserTrafficCounters result;
    const auto entry = accounts_.find(accounting_key);
    if (entry == accounts_.end()) return result;
    auto& bucket = entry->second;
    result.users.reserve(bucket.traffic.size());
    for (auto it = bucket.traffic.begin(); it != bucket.traffic.end();) {
        auto& account = it->second;
        const UserTraffic available{
            account.completed.upload - account.snapshotted.upload,
            account.completed.download - account.snapshotted.download,
        };
        if (available.upload || available.download) {
            result.users.emplace(it->first, available);
            account.completed.upload -= available.upload;
            account.completed.download -= available.download;
        }
        if (account.active == 0 && account.completed.upload == 0 &&
            account.completed.download == 0) {
            it = bucket.traffic.erase(it);
        } else {
            ++it;
        }
    }
    if (bucket.traffic.empty()) {
        accounts_.erase(entry);
        MaybeShrinkHashContainer(accounts_, 8);
    } else {
        MaybeShrinkHashContainer(bucket.traffic);
    }
    return result;
}

void SessionTrackingState::MergeCompletedTraffic(
    std::string_view accounting_key, UserTrafficCounters& source) {
    if (accounting_key.empty() || source.empty()) return;
    auto entry = accounts_.find(accounting_key);
    const bool inserted = entry == accounts_.end();
    if (inserted) {
        entry = accounts_.try_emplace(std::string{accounting_key}).first;
        entry->second.key = entry->first;
    }
    auto& bucket = entry->second;
    try {
        for (auto it = source.users.begin(); it != source.users.end();) {
            auto& completed = bucket.traffic.try_emplace(it->first).first->second.completed;
            completed.upload += it->second.upload;
            completed.download += it->second.download;
            it = source.users.erase(it);
        }
    } catch (...) {
        if (inserted && bucket.traffic.empty()) accounts_.erase(entry);
        throw;
    }
}

}  // namespace app
