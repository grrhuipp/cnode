#include "controller/traffic_journal.hpp"
#include "controller/traffic_journal_format.hpp"
#include "infra/json.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>
#include <system_error>
#include <unordered_map>

namespace controller {

namespace {

[[noreturn]] void SystemFailure(const char* operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}
std::string Identity(const infra::PanelConfig& config) {
    if (config.TrafficJournalDir.empty()) {
        throw std::invalid_argument("traffic journal directory is required");
    }
    if (config.Name.empty() || config.NodeIDs.Values().size() != 1) {
        throw std::invalid_argument("traffic journal requires a panel name and one node identity");
    }
    const auto identity = infra::serialize(infra::array{
        config.Name, config.APIHost, config.NodeType, config.NodeIDs.Front()});
    return Sha256Hex(identity);
}
std::optional<RecordState> EntryRecordState(const std::filesystem::directory_entry& entry) {
    return ParseRecordName(entry.path().filename().native());
}

}  // namespace

TrafficJournal::TrafficJournal(const infra::PanelConfig& config)
    : directory_(config.TrafficJournalDir / Identity(config)) {
    std::filesystem::create_directories(directory_);
    directory_fd_ = ::open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd_ < 0) SystemFailure("open traffic journal directory");
    try {
        const auto parent_path = directory_.parent_path();
        ScopedFd parent(::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
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
            if (entry.path().extension() == kTemporarySuffix) {
                std::filesystem::remove(entry.path());
            }
        }
        SyncDirectory();
        if (::fsync(parent.fd) != 0) SystemFailure("sync traffic journal parent");
        auto ancestor_path = parent_path.parent_path();
        if (ancestor_path.empty()) ancestor_path = ".";
        ScopedFd ancestor(::open(ancestor_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
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
    failed_ = true;
}
void TrafficJournal::SyncDirectory() {
    if (::fsync(directory_fd_) != 0) SystemFailure("sync traffic journal directory");
}
void TrafficJournal::Append(const app::UserTrafficCounters& traffic) {
    if (traffic.empty()) return;
    CheckHealthy();
    constexpr uint64_t max_value = static_cast<uint64_t>(INT64_MAX);
    infra::array rows;
    for (const auto& [uid, value] : traffic.users) {
        if (uid <= 0 || value.upload > max_value || value.download > max_value) {
            throw std::runtime_error("traffic exceeds UniProxy signed integer range");
        }
        if (value.upload == 0 && value.download == 0) continue;
        rows.push_back(infra::array{uid, value.upload, value.download});
    }
    if (rows.empty()) return;
    const auto text = infra::serialize(infra::value(std::move(rows)));
    size_t bytes = 0, records = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
        const auto filename = entry.path().filename().native();
        if (!ParseRecordName(filename)) continue;
        struct stat st{};
        if (::fstatat(directory_fd_, filename.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            SystemFailure("stat traffic journal record");
        }
        if (!S_ISREG(st.st_mode) || st.st_size < 0) {
            throw std::runtime_error("invalid traffic journal record type");
        }
        const auto size = static_cast<size_t>(st.st_size);
        if (size > kMaxBytes || bytes > kMaxBytes - size) {
            throw std::runtime_error("traffic journal byte limit reached; reconcile unknown records");
        }
        bytes += size;
        ++records;
    }
    if (records >= kMaxRecords || text.size() > kMaxBytes - bytes) {
        throw std::runtime_error("traffic journal limit reached; counters retained, reconcile unknown records");
    }
    std::string name(kRecordPrefix);
    name.append(kRecordIdSize, 'X');
    name += kTemporarySuffix;
    auto temporary = (directory_ / name).string();
    ScopedFd file(::mkostemps(temporary.data(), static_cast<int>(kTemporarySuffix.size()),
                              O_CLOEXEC));
    if (file.fd < 0) SystemFailure("create traffic journal record");
    bool published = false;
    try {
        if (!WriteAllFd(file.fd, text)) SystemFailure("write traffic journal record");
        if (::fsync(file.fd) != 0) SystemFailure("sync traffic journal record");
        const auto temporary_name = std::filesystem::path(temporary).filename().native();
        const auto ready = directory_ /
            RecordNameWithState(temporary_name, RecordState::Ready);
        const auto unknown = directory_ /
            RecordNameWithState(temporary_name, RecordState::Unknown);
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
    CheckHealthy();
    try {
        Batch result;
        std::unordered_map<int64_t, api::UserTraffic> merged;
        size_t bytes = 0;
        for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
            if (EntryRecordState(entry) != RecordState::Ready) continue;
            const auto text = ReadRecord(directory_fd_, entry.path().filename().c_str());
            if (result.records.size() >= kMaxRecords || text.size() > kMaxBytes - bytes) {
                throw std::runtime_error("traffic journal exceeds replay bounds");
            }
            bytes += text.size();
            VisitRecordRows(text, [&merged](const RecordRow& row) {
                auto& value = merged[row.uid];
                value.UID = row.uid;
                if (row.upload > INT64_MAX - value.Upload || row.download > INT64_MAX - value.Download) {
                    throw std::runtime_error("traffic batch exceeds UniProxy signed integer range");
                }
                value.Upload += row.upload;
                value.Download += row.download;
            });
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
    CheckHealthy();
    if (batch.records.empty()) return;
    try {
        for (auto& path : batch.records) {
            const auto unknown = directory_ / RecordNameWithState(
                path.filename().native(), RecordState::Unknown);
            if (std::filesystem::symlink_status(unknown).type() != std::filesystem::file_type::not_found) {
                failed_ = true;
                throw std::runtime_error("traffic journal unknown record collision");
            }
            std::filesystem::rename(path, unknown);
            path = unknown;
        }
        SyncDirectory();
    } catch (...) { failed_ = true; throw; }
}
void TrafficJournal::Acknowledge(const Batch& batch) {
    CheckHealthy();
    if (batch.records.empty()) return;
    try {
        for (const auto& path : batch.records) std::filesystem::remove(path);
        SyncDirectory();
    } catch (...) { failed_ = true; throw; }
}
size_t TrafficJournal::UnknownCount() {
    size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory_)) {
        if (EntryRecordState(entry) == RecordState::Unknown) ++count;
    }
    return count;
}

}  // namespace controller
