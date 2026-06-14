#include "acppnode/common/serverstatus.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace acpp::serverstatus {
namespace {

[[nodiscard]] double DiskUsedPercent() {
    std::error_code ec;
    const auto space = std::filesystem::space("/", ec);
    if (ec || space.capacity == 0) {
        return 0.0;
    }
    const auto used = space.capacity - space.available;
    return static_cast<double>(used) * 100.0 / static_cast<double>(space.capacity);
}

#ifdef __linux__
struct CpuTimes {
    uint64_t idle = 0;
    uint64_t total = 0;
};

[[nodiscard]] std::optional<CpuTimes> ReadCpuTimes() {
    std::ifstream stat("/proc/stat");
    std::string cpu;
    uint64_t user = 0;
    uint64_t nice = 0;
    uint64_t system = 0;
    uint64_t idle = 0;
    uint64_t iowait = 0;
    uint64_t irq = 0;
    uint64_t softirq = 0;
    uint64_t steal = 0;
    if (!(stat >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal)) {
        return std::nullopt;
    }
    if (cpu != "cpu") {
        return std::nullopt;
    }
    CpuTimes times;
    times.idle = idle + iowait;
    times.total = user + nice + system + idle + iowait + irq + softirq + steal;
    return times;
}

[[nodiscard]] double CpuUsedPercent() {
    static std::optional<CpuTimes> previous;
    const auto current = ReadCpuTimes();
    if (!current) {
        return 0.0;
    }
    if (!previous) {
        previous = current;
        return 0.0;
    }

    const uint64_t total_delta = current->total - previous->total;
    const uint64_t idle_delta = current->idle - previous->idle;
    previous = current;
    if (total_delta == 0 || idle_delta > total_delta) {
        return 0.0;
    }
    return static_cast<double>(total_delta - idle_delta) * 100.0
        / static_cast<double>(total_delta);
}

[[nodiscard]] double MemUsedPercent() {
    std::ifstream meminfo("/proc/meminfo");
    std::string key;
    uint64_t value = 0;
    std::string unit;
    uint64_t total = 0;
    uint64_t available = 0;

    while (meminfo >> key >> value >> unit) {
        if (key == "MemTotal:") {
            total = value;
        } else if (key == "MemAvailable:") {
            available = value;
        }
        if (total != 0 && available != 0) {
            break;
        }
    }

    if (total == 0 || available > total) {
        return 0.0;
    }
    return static_cast<double>(total - available) * 100.0
        / static_cast<double>(total);
}

[[nodiscard]] uint64_t UptimeSeconds() {
    std::ifstream uptime_file("/proc/uptime");
    double uptime = 0.0;
    if (uptime_file >> uptime && uptime > 0.0) {
        return static_cast<uint64_t>(uptime);
    }
    return 0;
}
#else
[[nodiscard]] double CpuUsedPercent() {
    return 0.0;
}

[[nodiscard]] double MemUsedPercent() {
    return 0.0;
}

[[nodiscard]] uint64_t UptimeSeconds() {
#ifdef _WIN32
    return static_cast<uint64_t>(GetTickCount64() / 1000ULL);
#else
    static const auto started_at = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::steady_clock::now() - started_at;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
#endif
}
#endif

}  // namespace

api::NodeStatus GetSystemInfo() {
    api::NodeStatus status;
    status.CPU = CpuUsedPercent();
    status.Mem = MemUsedPercent();
    status.Disk = DiskUsedPercent();
    status.Uptime = UptimeSeconds();
    return status;
}

}  // namespace acpp::serverstatus
