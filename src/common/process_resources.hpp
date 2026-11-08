#pragma once

#include <cerrno>
#include <cstddef>
#include <optional>

#include <dirent.h>
#include <sys/resource.h>


struct ProcessDescriptors {
    std::optional<size_t> open;
    std::optional<size_t> soft_limit;
    bool soft_limit_unlimited = false;
};

// Control-thread diagnostics only. Unavailable counters remain unknown, not zero.
// Excludes the temporary directory descriptor used by this sample.
[[nodiscard]] inline ProcessDescriptors ReadProcessDescriptors() noexcept {
    ProcessDescriptors result;
    rlimit limits{};
    if (::getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        result.soft_limit_unlimited = limits.rlim_cur == RLIM_INFINITY;
        if (!result.soft_limit_unlimited) {
            result.soft_limit = static_cast<size_t>(limits.rlim_cur);
        }
    }
    if (DIR* directory = ::opendir("/proc/self/fd")) {
        size_t count = 0;
        errno = 0;
        while (const auto* entry = ::readdir(directory)) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++count;
        }
        const bool complete = errno == 0;
        ::closedir(directory);
        if (complete && count > 0) result.open = count - 1;
    }
    return result;
}

