#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"

#include <cstddef>
#include <limits>
#include <utility>

namespace acpp::worker_detail {

// Owner-thread-only product limits, shared by every native UDP ingress in a Worker.
// The budget must outlive session owners and pending asynchronous reply sends.
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
            if (budget_) --budget_->usage_.associations;
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
                --budget_->usage_.datagrams;
                budget_->usage_.payload_capacity -= capacity_;
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

    [[nodiscard]] Usage GetUsage() const noexcept { return usage_; }
    [[nodiscard]] AssociationLease AcquireAssociation() noexcept {
        if (usage_.associations >= limits_.associations) return {};
        ++usage_.associations;
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
        if (usage_.datagrams >= limits_.datagrams || capacity > limits_.payload_capacity ||
            usage_.payload_capacity > limits_.payload_capacity - capacity) return {};
        ++usage_.datagrams;
        usage_.payload_capacity += capacity;
        return PayloadReservation{*this, capacity};
    }

private:
    Limits limits_;
    Usage usage_;
};

} // namespace acpp::worker_detail
