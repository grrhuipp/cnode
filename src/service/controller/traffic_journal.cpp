#include "traffic_journal.hpp"

#include "infra/json.hpp"
#include "infra/json_field.hpp"
#include <openssl/sha.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <map>
#include <stdexcept>
#include <system_error>
#include <unordered_map>

namespace controller {
namespace {
[[noreturn]] void SystemFailure(const char* operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}
int64_t ReadCounter(const json::value& value) {
    const auto number = JsonUnsignedInteger(value);
    if (!number || *number > INT64_MAX) {
        throw std::runtime_error("invalid traffic journal integer");
    }
    return static_cast<int64_t>(*number);
}
struct File {
    int fd;
    ~File() { if (fd >= 0) ::close(fd); }
};
std::string Identity(const PanelConfig& config) {
    if (config.TrafficJournalDir.empty()) {
        throw std::invalid_argument("traffic journal directory is required");
    }
    if (config.Name.empty() || config.NodeIDs.Values().size() != 1) {
        throw std::invalid_argument("traffic journal requires a panel name and one node identity");
    }
    const auto identity = json::serialize(json::array{
        config.Name, config.APIHost, config.NodeType, config.NodeIDs.Front()});
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(identity.data()), identity.size(), digest.data());
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
std::string ReadRecord(const std::filesystem::path& path) {
    File file{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (file.fd < 0) SystemFailure("open traffic record");
    struct stat info{};
    if (::fstat(file.fd, &info) != 0) SystemFailure("stat traffic record");
    if (!S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) > TrafficJournal::kMaxBytes) {
        throw std::runtime_error("invalid traffic journal record size/type");
    }
    std::string text(static_cast<size_t>(info.st_size), '\0');
    size_t offset = 0;
    while (offset != text.size()) {
        const auto count = ::read(file.fd, text.data() + offset, text.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) SystemFailure("read traffic record");
        if (count == 0) throw std::runtime_error("truncated traffic journal record");
        offset += static_cast<size_t>(count);
    }
    return text;
}
}

TrafficJournal::TrafficJournal(const PanelConfig& config)
    : directory_(config.TrafficJournalDir / Identity(config)) {
    std::filesystem::create_directories(directory_);
    directory_fd_ = ::open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd_ < 0) SystemFailure("open traffic journal directory");
    try {
        const auto parent_path = directory_.parent_path();
        File parent{::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
        if (parent.fd < 0) SystemFailure("open traffic journal parent");
        if (::fchmod(parent.fd, 0700) != 0) SystemFailure("protect traffic journal parent");
        if (::fchmod(directory_fd_, 0700) != 0) SystemFailure("protect traffic journal directory");
        lock_fd_ = ::openat(directory_fd_, ".lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock_fd_ < 0) SystemFailure("open traffic journal lock");
        if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) SystemFailure("lock traffic journal");
        if (::fchmod(lock_fd_, 0600) != 0) SystemFailure("protect traffic journal lock");
        // Temporary files were never published or transmitted. A crashed worker's
        // unsampled in-memory counters cannot be reconstructed from these files.
        for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
            if (entry.path().extension() == ".tmp") std::filesystem::remove(entry.path());
        }
        SyncDirectory();
        if (::fsync(parent.fd) != 0) SystemFailure("sync traffic journal parent");
        auto ancestor_path = parent_path.parent_path();
        if (ancestor_path.empty()) ancestor_path = ".";
        File ancestor{::open(ancestor_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
        if (ancestor.fd < 0 || ::fsync(ancestor.fd) != 0) SystemFailure("sync traffic journal root");
    } catch (...) {
        if (lock_fd_ >= 0) ::close(lock_fd_);
        ::close(directory_fd_);
        throw;
    }
}
TrafficJournal::~TrafficJournal() {
    if (lock_fd_ >= 0) ::close(lock_fd_);
    if (directory_fd_ >= 0) ::close(directory_fd_);
}
void TrafficJournal::CheckHealthy() const {
    if (failed_) throw std::runtime_error("traffic journal I/O failed; reporting suspended until restart and reconciliation");
}
void TrafficJournal::Suspend() noexcept {
    std::lock_guard lock(mutex_);
    failed_ = true;
}
void TrafficJournal::SyncDirectory() {
    if (::fsync(directory_fd_) != 0) SystemFailure("sync traffic journal directory");
}
void TrafficJournal::Append(const app::UserTrafficSnapshot& traffic) {
    if (traffic.empty()) return;
    std::lock_guard lock(mutex_);
    CheckHealthy();
    constexpr uint64_t max_value = static_cast<uint64_t>(INT64_MAX);
    std::map<int64_t, app::UserTraffic> merged;
    const auto merge_rows = [&](const app::UserTrafficCounters& counters) {
        for (const auto& [uid, value] : counters) {
            if (uid <= 0 || value.upload > max_value || value.download > max_value) {
                throw std::runtime_error("traffic exceeds UniProxy signed integer range");
            }
            if (value.upload == 0 && value.download == 0) continue;
            auto& merged_entry = merged[uid];
            if (merged_entry.upload > max_value - value.upload ||
                merged_entry.download > max_value - value.download) {
                throw std::runtime_error("traffic exceeds UniProxy signed integer range");
            }
            merged_entry.upload += value.upload;
            merged_entry.download += value.download;
        }
    };
    merge_rows(traffic);
    for (const auto& token : traffic.domains) merge_rows(token.counters);
    if (merged.empty()) return;
    json::array rows;
    for (const auto& [uid, value] : merged) {
        rows.push_back(json::array{uid, value.upload, value.download});
    }
    const auto text = json::serialize(json::value(std::move(rows)));
    size_t bytes = 0, records = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
        if (entry.path().extension() != ".ready" && entry.path().extension() != ".unknown") continue;
        const auto status = entry.symlink_status();
        if (!std::filesystem::is_regular_file(status)) {
            throw std::runtime_error("invalid traffic journal record type");
        }
        const auto size = entry.file_size();
        if (size > kMaxBytes || bytes > kMaxBytes - size) {
            throw std::runtime_error("traffic journal byte limit reached; reconcile unknown records");
        }
        bytes += size;
        ++records;
    }
    if (records >= kMaxRecords || text.size() > kMaxBytes - bytes) {
        throw std::runtime_error("traffic journal limit reached; counters retained, reconcile unknown records");
    }
    auto temporary = (directory_ / "batch-XXXXXX.tmp").string();
    File file{::mkostemps(temporary.data(), 4, O_CLOEXEC)};
    if (file.fd < 0) SystemFailure("create traffic journal record");
    bool published = false;
    try {
        size_t offset = 0;
        while (offset != text.size()) {
            const auto count = ::write(file.fd, text.data() + offset, text.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) SystemFailure("write traffic journal record");
            offset += static_cast<size_t>(count);
        }
        if (::fsync(file.fd) != 0) SystemFailure("sync traffic journal record");
        auto ready = std::filesystem::path(temporary);
        ready.replace_extension(".ready");
        auto unknown = ready;
        unknown.replace_extension(".unknown");
        if (std::filesystem::symlink_status(ready).type() != std::filesystem::file_type::not_found ||
            std::filesystem::symlink_status(unknown).type() != std::filesystem::file_type::not_found) {
            throw std::runtime_error("traffic journal record identity collision");
        }
        std::filesystem::rename(temporary, ready);
        published = true;
        SyncDirectory();
    } catch (...) {
        if (!published) {
            std::error_code ec;
            std::filesystem::remove(temporary, ec);
        } else {
            // Publication already happened. Do not collect/send again in this
            // process: the worker deliberately retains its original counters.
            failed_ = true;
        }
        throw;
    }
}
TrafficJournal::Batch TrafficJournal::Prepare() {
    std::lock_guard lock(mutex_);
    CheckHealthy();
    try {
        Batch result;
        std::unordered_map<int64_t, api::UserTraffic> merged;
        size_t bytes = 0;
        for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
            if (entry.path().extension() != ".ready") continue;
            const auto text = ReadRecord(entry.path());
            if (result.records.size() >= kMaxRecords || text.size() > kMaxBytes - bytes) {
                throw std::runtime_error("traffic journal exceeds replay bounds");
            }
            bytes += text.size();
            const auto parsed = json::parse(text);
            if (!parsed.is_array()) throw std::runtime_error("invalid traffic journal record");
            for (const auto& item : parsed.as_array()) {
                if (!item.is_array()) throw std::runtime_error("invalid traffic journal row");
                const auto& row = item.as_array();
                if (row.size() != 3) throw std::runtime_error("invalid traffic journal row");
                const auto uid = ReadCounter(row[0]);
                const auto up = ReadCounter(row[1]);
                const auto down = ReadCounter(row[2]);
                if (uid <= 0 || up < 0 || down < 0 || (up == 0 && down == 0)) {
                    throw std::runtime_error("invalid traffic journal counters");
                }
                auto& value = merged[uid];
                value.UID = uid;
                if (up > INT64_MAX - value.Upload || down > INT64_MAX - value.Download) {
                    throw std::runtime_error("traffic batch exceeds UniProxy signed integer range");
                }
                value.Upload += up;
                value.Download += down;
            }
            result.records.push_back(entry.path());
        }
        result.traffic.reserve(merged.size());
        for (const auto& [uid, value] : merged) result.traffic.push_back(value);
        return result;
    } catch (...) {
        failed_ = true;
        throw;
    }
}
void TrafficJournal::Begin(Batch& batch) {
    std::lock_guard lock(mutex_);
    CheckHealthy();
    if (batch.records.empty()) return;
    try {
        for (auto& path : batch.records) {
            auto unknown = path;
            unknown.replace_extension(".unknown");
            if (std::filesystem::symlink_status(unknown).type() != std::filesystem::file_type::not_found) {
                failed_ = true;
                throw std::runtime_error("traffic journal unknown record collision");
            }
            std::filesystem::rename(path, unknown);
            path = std::move(unknown);
        }
        SyncDirectory();
    } catch (...) { failed_ = true; throw; }
}
void TrafficJournal::Acknowledge(const Batch& batch) {
    std::lock_guard lock(mutex_);
    CheckHealthy();
    if (batch.records.empty()) return;
    try {
        for (const auto& path : batch.records) std::filesystem::remove(path);
        SyncDirectory();
    } catch (...) { failed_ = true; throw; }
}
size_t TrafficJournal::UnknownCount() {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
        if (entry.path().extension() == ".unknown") ++count;
    }
    return count;
}
} // namespace controller
