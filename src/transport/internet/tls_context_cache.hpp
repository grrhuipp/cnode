#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <utility>

namespace acpp::transport::internet {

template <typename Context, typename Map>
class BoundedTlsContextCache {
public:
    explicit BoundedTlsContextCache(std::size_t max_entries)
        : max_entries_(max_entries) {}

    [[nodiscard]] Context* Find(const std::string& key) noexcept {
        const auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : it->second.get();
    }

    [[nodiscard]] Context* Insert(
        std::string key,
        std::unique_ptr<Context> context) {
        if (!context || max_entries_ == 0) return nullptr;
        if (auto* existing = Find(key)) return existing;

        if (entries_.size() >= max_entries_) {
            entries_.erase(entries_.begin());
        }
        auto [it, inserted] = entries_.emplace(
            std::move(key), std::move(context));
        return inserted ? it->second.get() : nullptr;
    }

private:
    std::size_t max_entries_;
    Map entries_;
};

}  // namespace acpp::transport::internet
