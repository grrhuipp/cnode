#include <gtest/gtest.h>

#include "service/controller/traffic_journal.hpp"
#include "infra/json.hpp"

#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
using ::controller::TrafficJournal;
::app::UserTrafficSnapshot Sample() {
    ::app::UserTrafficSnapshot result;
    result.users.emplace(42, ::app::UserTraffic{17, 29});
    return result;
}
void CheckSample(const TrafficJournal::Batch& batch) {
    Check(batch.traffic.size() == 1 && batch.traffic[0].UID == 42 &&
          batch.traffic[0].Upload == 17 && batch.traffic[0].Download == 29,
          "durable traffic changed across lifecycle");
}
void CrashWrite(const ::PanelConfig& config, bool begin) {
    const auto child = ::fork();
    Check(child >= 0, "fork failed");
    if (child == 0) {
        try {
            TrafficJournal journal(config);
            journal.Append(Sample());
            if (begin) {
                auto batch = journal.Prepare();
                journal.Begin(batch);
            }
            // No C++ destructors or graceful daemon shutdown.
            ::_exit(0);
        } catch (...) { ::_exit(1); }
    }
    int status = 0;
    Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "crash fixture failed");
}
}
TEST(TrafficJournal, Contract) {
    char name[] = "/tmp/cnode-traffic-journal-XXXXXX";
    const auto* created = ::mkdtemp(name);
    Check(created != nullptr, "temporary directory failed");
    const std::filesystem::path root(created);
    try {
        ::PanelConfig config;
        config.Name = "test";
        config.APIHost = "http://127.0.0.1:12345";
        config.Key = "not-written-to-journal";
        config.NodeIDs = ::PanelNodeIds::Parse(::json::array{1});
        config.TrafficJournalDir = root / "journal";
        std::filesystem::path directory;
        CrashWrite(config, false);
        {
            TrafficJournal journal(config);
            directory = journal.Directory();
            auto batch = journal.Prepare();
            CheckSample(batch);
            Check(batch.records.size() == 1 && journal.UnknownCount() == 0, "ready recovery failed");
            bool locked = false;
            try { TrafficJournal duplicate(config); } catch (const std::exception&) { locked = true; }
            Check(locked, "second accounting writer was admitted");
            journal.Begin(batch);
            Check(journal.Prepare().traffic.empty() && journal.UnknownCount() == 1,
                  "unknown batch remained eligible for automatic retry");
            journal.Acknowledge(batch);
            Check(journal.UnknownCount() == 0, "accepted batch was not removed");
        }
        CrashWrite(config, true);
        {
            TrafficJournal journal(config);
            Check(journal.UnknownCount() == 1 && journal.Prepare().traffic.empty(),
                  "process restart retried an ambiguous request");
            struct stat info{};
            Check(::stat(directory.c_str(), &info) == 0 && (info.st_mode & 0777) == 0700,
                  "journal directory is not private");
            for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                if (entry.path().extension() == ".unknown") {
                    Check(::stat(entry.path().c_str(), &info) == 0 && (info.st_mode & 0777) == 0600,
                          "journal record is not private");
                    std::filesystem::remove(entry.path());
                }
            }
            const auto huge = directory / "batch-limit0.unknown";
            const int fd = ::open(huge.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
            Check(fd >= 0 && ::ftruncate(fd, TrafficJournal::kMaxBytes) == 0, "limit fixture failed");
            ::close(fd);
            bool rejected = false;
            try { journal.Append(Sample()); } catch (const std::exception&) { rejected = true; }
            Check(rejected && journal.Prepare().traffic.empty(), "full journal silently accepted or discarded a delta");
            std::filesystem::remove(huge);
            for (size_t i = 0; i < TrafficJournal::kMaxRecords; ++i) {
                std::ofstream(directory / (std::to_string(i) + ".unknown")) << "[]";
            }
            rejected = false;
            try { journal.Append(Sample()); } catch (const std::exception&) { rejected = true; }
            Check(rejected, "journal record count is not bounded");
        }
        config.Name = "different-tenant";
        {
            TrafficJournal isolated(config);
            Check(isolated.Directory() != directory && isolated.UnknownCount() == 0,
                  "different panel identity reused accounting state");
            ::app::UserTrafficSnapshot domain_only;
            ::app::DomainTrafficSnapshot first, second;
            first.counters.users.emplace(42, ::app::UserTraffic{5, 8});
            second.counters.users.emplace(42, ::app::UserTraffic{12, 21});
            domain_only.domains.push_back(std::move(first));
            domain_only.domains.push_back(std::move(second));
            Check(!domain_only.empty(), "domain-only traffic was mistaken for an empty snapshot");
            isolated.Append(domain_only);
            auto batch = isolated.Prepare();
            CheckSample(batch);
            isolated.Begin(batch);
            isolated.Acknowledge(batch);
        }
        std::filesystem::remove_all(root);
        std::cout << "traffic journal: ready crash recovery, unknown quarantine, bounds and isolation ok\n";
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
}
