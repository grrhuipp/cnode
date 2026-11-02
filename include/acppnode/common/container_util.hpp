#pragma once

#include <algorithm>
#include <cstddef>

namespace acpp {

// 当哈希容器在流量高峰后变得非常稀疏时，主动回缩 bucket，
// 避免 burst 后长时间保留大块空桶内存。
template <typename HashContainer>
inline void MaybeShrinkHashContainer(
    HashContainer& container,
    size_t keep_min_buckets = 64,
    size_t sparse_ratio = 8) noexcept {
    const size_t buckets = container.bucket_count();
    if (buckets <= keep_min_buckets || sparse_ratio == 0) {
        return;
    }

    const size_t size = container.size();
    if (size == 0) {
        try {
            container.rehash(keep_min_buckets);
        } catch (...) {
            // 内存回缩属于最佳努力优化，失败时不影响主流程。
        }
        return;
    }

    if (buckets / sparse_ratio <= size) {
        return;
    }

    const size_t target_buckets = std::max(keep_min_buckets, size * 2);
    if (target_buckets < buckets) {
        try {
            container.rehash(target_buckets);
        } catch (...) {
            // 内存回缩属于最佳努力优化，失败时不影响主流程。
        }
    }
}

template <typename SequenceContainer>
inline void TryShrinkSequence(SequenceContainer& container) noexcept {
    try {
        container.shrink_to_fit();
    } catch (...) {
        // 队列/顺序容器回缩属于最佳努力优化，失败时不影响主流程。
    }
}

}  // namespace acpp
