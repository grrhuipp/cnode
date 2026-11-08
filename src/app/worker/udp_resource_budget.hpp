#pragma once

#include "common/buf/multi_buffer.hpp"

#include <atomic>
#include <cstddef>
#include <limits>
#include <utility>

namespace worker_detail {

// Limits are Worker-scoped. Reservation release is atomic so a frozen native
// association can transfer its leases without borrowing the old Worker thread.
class UdpResourceBudget final {
public:
    struct Limits {
        size_t associations = 4096;
        size_t datagrams = 8192;
        size_t payload_capacity = 64 * 1024 * 1024;
    };
    struct Usage {
        size_t associations = 0;
        size_t datagrams = 0;
        size_t payload_capacity = 0;
    };

    class AssociationLease final {
    public:
        AssociationLease() noexcept = default;
        ~AssociationLease() { Reset(); }
        AssociationLease(const AssociationLease&) = delete;
        AssociationLease& operator=(const AssociationLease&) = delete;
        AssociationLease(AssociationLease&& other) noexcept
            : budget_(std::exchange(other.budget_, nullptr)) {}
        AssociationLease& operator=(AssociationLease&& other) noexcept {
            if (this != &other) {
                Reset();
                budget_ = std::exchange(other.budget_, nullptr);
            }
            return *this;
        }
        explicit operator bool() const noexcept { return budget_ != nullptr; }
    private:
        friend class UdpResourceBudget;
        explicit AssociationLease(UdpResourceBudget& budget) noexcept : budget_(&budget) {}
        void Reset() noexcept {
            if (budget_) budget_->associations_.fetch_sub(1, std::memory_order_relaxed);
            budget_ = nullptr;
        }
        UdpResourceBudget* budget_ = nullptr;
    };

    class PayloadReservation final {
    public:
        PayloadReservation() noexcept = default;
        ~PayloadReservation() { Reset(); }
        PayloadReservation(const PayloadReservation&) = delete;
        PayloadReservation& operator=(const PayloadReservation&) = delete;
        PayloadReservation(PayloadReservation&& other) noexcept
            : budget_(std::exchange(other.budget_, nullptr)), capacity_(other.capacity_) {}
        PayloadReservation& operator=(PayloadReservation&& other) noexcept {
            if (this != &other) {
                Reset();
                budget_ = std::exchange(other.budget_, nullptr);
                capacity_ = other.capacity_;
            }
            return *this;
        }
        explicit operator bool() const noexcept { return budget_ != nullptr; }
    private:
        friend class UdpResourceBudget;
        PayloadReservation(UdpResourceBudget& budget, size_t capacity) noexcept
            : budget_(&budget), capacity_(capacity) {}
        void Reset() noexcept {
            if (budget_) {
                budget_->datagrams_.fetch_sub(1, std::memory_order_relaxed);
                budget_->payload_capacity_.fetch_sub(capacity_, std::memory_order_relaxed);
            }
            budget_ = nullptr;
        }
        UdpResourceBudget* budget_ = nullptr;
        size_t capacity_ = 0;
    };

    UdpResourceBudget() noexcept = default;
    explicit UdpResourceBudget(Limits limits) noexcept : limits_(limits) {}
    UdpResourceBudget(const UdpResourceBudget&) = delete;
    UdpResourceBudget& operator=(const UdpResourceBudget&) = delete;

    [[nodiscard]] Usage GetUsage() const noexcept {
        return {associations_.load(std::memory_order_relaxed),
                datagrams_.load(std::memory_order_relaxed),
                payload_capacity_.load(std::memory_order_relaxed)};
    }
    [[nodiscard]] AssociationLease AcquireAssociation() noexcept {
        if (!Acquire(associations_, 1, limits_.associations)) return {};
        return AssociationLease{*this};
    }
    [[nodiscard]] PayloadReservation ReservePayload(const buf::MultiBuffer& payload) noexcept {
        size_t capacity = 0;
        for (const auto* buffer : payload) {
            if (!buffer) continue;
            if (capacity > std::numeric_limits<size_t>::max() - buf::Buffer::kSize)
                return {};
            capacity += buf::Buffer::kSize;
        }
        if (!Acquire(datagrams_, 1, limits_.datagrams)) return {};
        if (!Acquire(payload_capacity_, capacity, limits_.payload_capacity)) {
            datagrams_.fetch_sub(1, std::memory_order_relaxed);
            return {};
        }
        return PayloadReservation{*this, capacity};
    }

private:
    static bool Acquire(std::atomic<size_t>& counter, size_t amount, size_t limit) noexcept {
        auto value = counter.load(std::memory_order_relaxed);
        do {
            if (amount > limit || value > limit - amount) return false;
        } while (!counter.compare_exchange_weak(value, value + amount,
                     std::memory_order_relaxed));
        return true;
    }
    Limits limits_;
    std::atomic<size_t> associations_{0};
    std::atomic<size_t> datagrams_{0};
    std::atomic<size_t> payload_capacity_{0};
};

} // namespace worker_detail
