#pragma once

#include <cerrno>
#include <cstddef>
#include <optional>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/resource.h>
#ifdef __linux__
#include <dirent.h>
#endif
#endif

namespace acpp {

struct ProcessDescriptors {
#ifdef _WIN32
    std::string_view kind = "handles";
#else
    std::string_view kind = "fds";
#endif
    std::optional<size_t> open;
    std::optional<size_t> soft_limit;
    bool soft_limit_unlimited = false;
};

// Control-thread diagnostics only. Unavailable counters remain unknown, not zero.
// Linux excludes the temporary directory descriptor used by this sample.
[[nodiscard]] inline ProcessDescriptors ReadProcessDescriptors() noexcept {
    ProcessDescriptors result;
#ifdef _WIN32
    DWORD count = 0;
    if (::GetProcessHandleCount(::GetCurrentProcess(), &count)) {
        result.open = count;
    }
#else
    rlimit limits{};
    if (::getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        result.soft_limit_unlimited = limits.rlim_cur == RLIM_INFINITY;
        if (!result.soft_limit_unlimited) {
            result.soft_limit = static_cast<size_t>(limits.rlim_cur);
        }
    }
#ifdef __linux__
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
#endif
#endif
    return result;
}

} // namespace acpp
