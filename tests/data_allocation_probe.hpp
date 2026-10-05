#pragma once

#include "acppnode/common/allocator.hpp"

// Test-local fault/observation hooks on the fixed data allocation domain.
// Installation and removal bracket all I/O in the case; no default PMR swap.
class DataAllocationProbe {
public:
    explicit DataAllocationProbe(
        acpp::memory::AllocationFaultProbe fault = nullptr,
        acpp::memory::AllocationObserver observer = nullptr) noexcept
        : previous_fault_(acpp::memory::allocation_fault_probe.exchange(fault)),
          previous_observer_(acpp::memory::allocation_observer.exchange(observer)) {}
    ~DataAllocationProbe() {
        acpp::memory::allocation_fault_probe = previous_fault_;
        acpp::memory::allocation_observer = previous_observer_;
    }
    DataAllocationProbe(const DataAllocationProbe&) = delete;
    DataAllocationProbe& operator=(const DataAllocationProbe&) = delete;
private:
    acpp::memory::AllocationFaultProbe previous_fault_;
    acpp::memory::AllocationObserver previous_observer_;
};
