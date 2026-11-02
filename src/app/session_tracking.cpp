#include "acppnode/app/session_tracking.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/string_hash.hpp"

namespace acpp::app {

struct SessionTrackingState::Account {
    UserTraffic completed;
    size_t active = 0;
};

struct SessionTrackingState::Impl : memory::ThreadAllocated {
    using Accounts = memory::ThreadLocalUnorderedMap<int64_t, Account>;
    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString, Accounts,
        TransparentStringHash, TransparentStringEq> accounts;
    ActiveSession* active_head = nullptr;
};

SessionTrackingState::SessionTrackingState()
    : impl_(std::make_unique<Impl>()) {}
SessionTrackingState::~SessionTrackingState() = default;
SessionTrackingState::SessionTrackingState(SessionTrackingState&&) noexcept = default;
SessionTrackingState& SessionTrackingState::operator=(SessionTrackingState&&) noexcept = default;

void SessionTrackingState::RegisterActiveSession(ActiveSession& node,
    std::string_view accounting_key, int64_t user_id, session::Traffic& traffic) {
    if (accounting_key.empty() || user_id <= 0 || node.linked) return;
    auto entry = impl_->accounts.find(accounting_key);
    const bool inserted = entry == impl_->accounts.end();
    if (inserted) entry = impl_->accounts.try_emplace(
        memory::ThreadLocalString{accounting_key}).first;
    try {
        auto& account = entry->second.try_emplace(user_id).first->second;
        node.account = &account;
        ++account.active;
    } catch (...) {
        if (inserted) impl_->accounts.erase(entry);
        throw;
    }
    node.tag = entry->first;
    node.user_id = user_id;
    node.traffic = &traffic;
    node.last_reported_up = 0;
    node.last_reported_down = 0;
    node.prev = nullptr;
    node.next = impl_->active_head;
    if (node.next) node.next->prev = &node;
    impl_->active_head = &node;
    node.linked = true;
}

void SessionTrackingState::UnregisterActiveSession(ActiveSession& node) noexcept {
    if (!node.linked) return;
    if (node.prev) node.prev->next = node.next;
    else impl_->active_head = node.next;
    if (node.next) node.next->prev = node.prev;
    auto& account = *node.account;
    account.completed.upload += node.traffic->bytes_up - node.last_reported_up;
    account.completed.download += node.traffic->bytes_down - node.last_reported_down;
    --account.active;
    node = {};
}

UserTrafficSnapshot SessionTrackingState::CollectAndResetTraffic(std::string_view accounting_key) {
    UserTrafficSnapshot result;
    const auto entry = impl_->accounts.find(accounting_key);
    if (entry == impl_->accounts.end()) return result;

    // Allocate the entire result before acknowledging any bytes. A failed
    // collection leaves both completed traffic and live cursors unchanged.
    result.users.reserve(entry->second.size());
    for (const auto& [user_id, account] : entry->second) {
        if (account.completed.upload || account.completed.download)
            result.users.emplace(user_id, account.completed);
    }
    for (auto* node = impl_->active_head; node; node = node->next) {
        if (node->tag != accounting_key) continue;
        const auto up = node->traffic->bytes_up - node->last_reported_up;
        const auto down = node->traffic->bytes_down - node->last_reported_down;
        if (up || down) {
            auto& total = result.users[node->user_id];
            total.upload += up;
            total.download += down;
        }
    }

    for (auto* node = impl_->active_head; node; node = node->next) {
        if (node->tag != accounting_key) continue;
        node->last_reported_up = node->traffic->bytes_up;
        node->last_reported_down = node->traffic->bytes_down;
    }
    for (auto it = entry->second.begin(); it != entry->second.end();) {
        if (it->second.active == 0) it = entry->second.erase(it);
        else {
            it->second.completed = {};
            ++it;
        }
    }
    if (entry->second.empty()) impl_->accounts.erase(entry);
    return result;
}

}  // namespace acpp::app
