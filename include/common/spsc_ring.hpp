#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <new>
#include <type_traits>

namespace common {

// Bounded single-producer single-consumer ring. Only the producer thread calls
// TryPush and only the consumer thread calls TryPop. The producer writes tail_
// and the consumer writes head_; each side keeps the other's index cached on
// its own cache line and rereads it only when the ring looks full or empty.
// A slot is published by the release store of tail_ and acquired by the
// consumer's acquire load; it is handed back by the release store of head_.
// Indexes grow monotonically, so there is no ABA and no CAS.
template <typename T, size_t Capacity>
    requires std::is_trivially_copyable_v<T> && (Capacity >= 2) &&
             ((Capacity & (Capacity - 1)) == 0)
class SpscRing final {
public:
    [[nodiscard]] bool TryPush(const T& value) noexcept {
        const size_t tail = producer_.tail.load(std::memory_order_relaxed);
        if (tail - producer_.cached_head == Capacity) {
            producer_.cached_head = consumer_.head.load(std::memory_order_acquire);
            if (tail - producer_.cached_head == Capacity) return false;
        }
        slots_[tail & (Capacity - 1)] = value;
        producer_.tail.store(tail + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool TryPop(T& value) noexcept {
        const size_t head = consumer_.head.load(std::memory_order_relaxed);
        if (head == consumer_.cached_tail) {
            consumer_.cached_tail = producer_.tail.load(std::memory_order_acquire);
            if (head == consumer_.cached_tail) return false;
        }
        value = slots_[head & (Capacity - 1)];
        consumer_.head.store(head + 1, std::memory_order_release);
        return true;
    }

    // Either side: whether the ring held nothing when observed. Pair with a
    // seq_cst fence when used to decide sleeping against a concurrent push.
    [[nodiscard]] bool Empty() const noexcept {
        return producer_.tail.load(std::memory_order_acquire) ==
               consumer_.head.load(std::memory_order_acquire);
    }

    // Producer side: whether TryPush would currently find room.
    [[nodiscard]] bool HasRoom() const noexcept {
        return producer_.tail.load(std::memory_order_relaxed) -
               consumer_.head.load(std::memory_order_acquire) < Capacity;
    }

private:
    static constexpr size_t kLine = 64;
    struct alignas(kLine) ProducerSide {
        std::atomic<size_t> tail{0};
        size_t cached_head = 0;
    };
    struct alignas(kLine) ConsumerSide {
        std::atomic<size_t> head{0};
        size_t cached_tail = 0;
    };

    ProducerSide producer_;
    ConsumerSide consumer_;
    alignas(kLine) std::array<T, Capacity> slots_{};
};

}  // namespace common
