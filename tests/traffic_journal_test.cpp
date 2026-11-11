#include <gtest/gtest.h>

#include "service/controller/traffic_journal.hpp"
#include "service/controller/traffic_journal_format.hpp"
#include "infra/json.hpp"

#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <format>

namespace {
using ::controller::TrafficJournal;
namespace journal_format = ::controller::traffic_journal;

::app::UserTrafficCounters Sample() {
    ::app::UserTrafficCounters result;
    result.users.emplace(42, ::app::UserTraffic{17, 29});
    return result;
}

class TrafficJournalTest : public testing::Test {
protected:
    void SetUp() override {
        char name[] = "/tmp/cnode-traffic-journal-XXXXXX";
        const auto* created = ::mkdtemp(name);
        ASSERT_NE(created, nullptr);
        root = created;
        config.Name = "test";
        config.APIHost = "http://127.0.0.1:12345";
        config.Key = "not-written-to-journal";
        config.NodeIDs = ::infra::PanelNodeIds::Parse(::json::array{1});
        config.TrafficJournalDir = root / "journal";
    }
    void TearDown() override {
        if (!root.empty()) {
            std::error_code error;
            std::filesystem::remove_all(root, error);
            EXPECT_FALSE(error) << error.message();
        }
    }
    void CrashWrite(bool begin) {
        const auto child = ::fork();
        ASSERT_GE(child, 0);
        if (child == 0) {
            try {
                TrafficJournal journal(config);
                journal.Append(Sample());
                if (begin) {
                    auto batch = journal.Prepare();
                    journal.Begin(batch);
                }
                // 模拟进程在析构与正常停机之前退出。
                ::_exit(0);
            } catch (...) { ::_exit(1); }
        }
        int status = 0;
        ASSERT_EQ(::waitpid(child, &status, 0), child);
        ASSERT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
    std::filesystem::path root;
    ::infra::PanelConfig config;
};

TEST_F(TrafficJournalTest, ReadyRecordSurvivesCrashAndAcknowledgementRemovesIt) {
    CrashWrite(false);
    TrafficJournal journal(config);
    auto batch = journal.Prepare();
    ASSERT_EQ(batch.traffic.size(), 1u);
    EXPECT_EQ(batch.traffic[0].UID, 42);
    EXPECT_EQ(batch.traffic[0].Upload, 17);
    EXPECT_EQ(batch.traffic[0].Download, 29);
    EXPECT_EQ(batch.records.size(), 1u);
    EXPECT_EQ(journal.UnknownCount(), 0u);
    journal.Begin(batch);
    EXPECT_TRUE(journal.Prepare().traffic.empty());
    EXPECT_EQ(journal.UnknownCount(), 1u);
    journal.Acknowledge(batch);
    EXPECT_EQ(journal.UnknownCount(), 0u);
    EXPECT_TRUE(journal.Prepare().traffic.empty());
}

TEST_F(TrafficJournalTest, AmbiguousRecordSurvivesCrashWithoutAutomaticRetry) {
    CrashWrite(true);
    TrafficJournal journal(config);
    EXPECT_EQ(journal.UnknownCount(), 1u);
    EXPECT_TRUE(journal.Prepare().traffic.empty());
}

TEST_F(TrafficJournalTest, CreatesPrivateJournalDirectoryAndDurableRecord) {
    TrafficJournal journal(config);
    journal.Append(Sample());
    auto batch = journal.Prepare();
    journal.Begin(batch);
    struct stat info{};
    ASSERT_EQ(::stat(journal.Directory().c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0700);
    size_t records = 0;
    for (const auto& entry : std::filesystem::directory_iterator(journal.Directory())) {
        if (entry.path().extension() != ".unknown") continue;
        ++records;
        ASSERT_EQ(::stat(entry.path().c_str(), &info), 0);
        EXPECT_EQ(info.st_mode & 0777, 0600);
    }
    EXPECT_EQ(records, 1u);
}

TEST_F(TrafficJournalTest, RejectsConcurrentAccountingWriterAndReleasesLockOnDestruction) {
    {
        TrafficJournal journal(config);
        EXPECT_THROW({ TrafficJournal duplicate(config); }, std::exception);
    }
    TrafficJournal reopened(config);
    reopened.Append(Sample());
    EXPECT_EQ(reopened.Prepare().records.size(), 1u);
}

TEST_F(TrafficJournalTest, ByteLimitRejectsDeltaWithoutPublishingReadyRecord) {
    TrafficJournal journal(config);
    const auto huge = journal.Directory() / "batch-limit0.unknown";
    const int fd = ::open(huge.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    ASSERT_GE(fd, 0);
    const int truncated = ::ftruncate(fd, journal_format::kMaxBytes);
    const int closed = ::close(fd);
    ASSERT_EQ(truncated, 0);
    ASSERT_EQ(closed, 0);
    EXPECT_THROW(journal.Append(Sample()), std::exception);
    EXPECT_TRUE(journal.Prepare().traffic.empty());
    EXPECT_TRUE(std::filesystem::exists(huge));
}

TEST_F(TrafficJournalTest, RecordCountLimitRejectsAdditionalDelta) {
    TrafficJournal journal(config);
    for (size_t i = 0; i < journal_format::kMaxRecords; ++i) {
        std::ofstream file(journal.Directory() / std::format("batch-{:06}.unknown", i));
        ASSERT_TRUE(file);
        file << "[]";
    }
    EXPECT_THROW(journal.Append(Sample()), std::exception);
    EXPECT_EQ(journal.UnknownCount(), journal_format::kMaxRecords);
    EXPECT_TRUE(journal.Prepare().traffic.empty());
}

TEST_F(TrafficJournalTest, PanelIdentityKeepsAccountingStateSeparate) {
    std::filesystem::path original;
    {
        TrafficJournal journal(config);
        original = journal.Directory();
        journal.Append(Sample());
        auto batch = journal.Prepare();
        journal.Begin(batch);
    }
    config.Name = "different-tenant";
    TrafficJournal isolated(config);
    EXPECT_NE(isolated.Directory(), original);
    EXPECT_EQ(isolated.UnknownCount(), 0u);
    EXPECT_TRUE(isolated.Prepare().traffic.empty());
}

TEST_F(TrafficJournalTest, MergesDurableDeltasBeforeAcknowledgement) {
    TrafficJournal journal(config);
    ::app::UserTrafficCounters first, second;
    first.users.emplace(42, ::app::UserTraffic{5, 8});
    second.users.emplace(42, ::app::UserTraffic{12, 21});
    journal.Append(first);
    journal.Append(second);
    auto batch = journal.Prepare();
    ASSERT_EQ(batch.traffic.size(), 1u);
    EXPECT_EQ(batch.traffic[0].UID, 42);
    EXPECT_EQ(batch.traffic[0].Upload, 17);
    EXPECT_EQ(batch.traffic[0].Download, 29);
    EXPECT_EQ(batch.records.size(), 2u);
    journal.Begin(batch);
    journal.Acknowledge(batch);
    EXPECT_TRUE(journal.Prepare().traffic.empty());
    EXPECT_EQ(journal.UnknownCount(), 0u);
}

TEST_F(TrafficJournalTest, CorruptReadyRecordFailsClosedAndPreservesDurableEvidence) {
    std::filesystem::path corrupt;
    {
        TrafficJournal journal(config);
        journal.Append(Sample());
        corrupt = journal.Directory() / "batch-broken.ready";
        std::ofstream(corrupt) << "[[42,17,-1]]";
        EXPECT_THROW((void)journal.Prepare(), std::runtime_error);
        EXPECT_TRUE(std::filesystem::exists(corrupt));
        EXPECT_THROW(journal.Append(Sample()), std::runtime_error);
    }
    std::filesystem::remove(corrupt);
    TrafficJournal recovered(config);
    auto batch = recovered.Prepare();
    ASSERT_EQ(batch.traffic.size(), 1u);
    EXPECT_EQ(batch.traffic[0].Upload, 17);
    EXPECT_EQ(batch.traffic[0].Download, 29);
}
}  // namespace
