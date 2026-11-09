#include "service/controller/controller.hpp"

#include "../../common/awaitable_batch.hpp"
#include "node_transaction.hpp"

#include "api/api.hpp"
#include "app/prepared_inbound.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "app/worker.hpp"
#include "common/asio_types.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
#include "features/routing/dispatch_policy.hpp"
#include "infra/json.hpp"
#include "infra/log.hpp"
#include "infra/panel_config.hpp"
#include "transport/internet/http_headers.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/thread_pool.hpp>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <format>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace controller {

// One cold-path disk thread shared by all panels. Admission is bounded and
// shutdown joins outstanding work. Cancellation never abandons a disk write:
// its completion must be observed before the caller releases borrowed state.
class JournalExecutor {
public:
    ~JournalExecutor() { pool_.join(); }

    template<class Function>
    net::awaitable<std::invoke_result_t<Function>> Run(Function function) {
        using Result = std::invoke_result_t<Function>;
        if (pending_.fetch_add(1, std::memory_order_relaxed) >= kCapacity) {
            pending_.fetch_sub(1, std::memory_order_relaxed);
            throw std::runtime_error("traffic journal executor queue is full");
        }
        Slot slot{this};
        const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
        co_await net::this_coro::throw_if_cancelled(false);
        std::exception_ptr failure;
        if constexpr (std::is_void_v<Result>) {
            try {
                co_await net::co_spawn(
                    pool_,
                    Invoke(std::move(slot), std::move(function)),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
            } catch (...) {
                failure = std::current_exception();
            }
            co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
            if (failure) std::rethrow_exception(failure);
            co_return;
        } else {
            std::optional<Result> result;
            try {
                result.emplace(co_await net::co_spawn(
                    pool_,
                    Invoke(std::move(slot), std::move(function)),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable)));
            } catch (...) {
                failure = std::current_exception();
            }
            co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
            if (failure) std::rethrow_exception(failure);
            co_return std::move(*result);
        }
    }
private:
    struct Slot {
        JournalExecutor* owner;
        explicit Slot(JournalExecutor* value) noexcept : owner(value) {}
        Slot(Slot&& other) noexcept : owner(std::exchange(other.owner, nullptr)) {}
        Slot(const Slot&) = delete;
        ~Slot() { if (owner) owner->pending_.fetch_sub(1, std::memory_order_relaxed); }
    };
    template<class Function>
    static net::awaitable<std::invoke_result_t<Function>> Invoke(
        [[maybe_unused]] Slot slot, Function function) {
        if constexpr (std::is_void_v<std::invoke_result_t<Function>>) {
            function();
            co_return;
        } else {
            co_return function();
        }
    }
    static constexpr size_t kCapacity = 64;
    net::thread_pool pool_{1};
    std::atomic<size_t> pending_{0};
};

namespace {

[[nodiscard]] StreamSettings MapPanelStreamSettings(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config) {
    StreamSettings stream;
    stream.network = node_config.TransportProtocol.empty()
        ? std::string(constants::protocol::kTcp)
        : node_config.TransportProtocol;

    // TLSEnable only declares that this cnode instance can terminate TLS.
    // The panel node still decides whether this particular inbound uses TLS.
    if (node_config.EnableReality) {
        stream.security = std::string(constants::protocol::kReality);
        stream.reality = node_config.Reality;
    } else if (ShouldEnableInboundTls(panel_config, node_config)) {
        stream.security = std::string(constants::protocol::kTls);
        stream.tls.cert_file = panel_config.TLSCert;
        stream.tls.key_file = panel_config.TLSKey;
        stream.tls.server_name = node_config.TLSServerName;
        stream.tls.pem = panel_config.TLSPem;
    }

    // Fill the transport sub-config first: normalization derives cached
    // fields (gRPC request path, XHTTP path, Host) from it.
    switch (ParseNetworkMode(stream.network)) {
    case NetworkMode::Ws:
        stream.ws.path = node_config.Path;
        if (!node_config.Host.empty()) {
            stream.ws.headers.emplace(
                transport::internet::NormalizeHttpHeaderName("Host"),
                node_config.Host);
        }
        break;
    case NetworkMode::HttpUpgrade:
        stream.http_upgrade.path = node_config.Path;
        stream.http_upgrade.host = node_config.Host;
        break;
    case NetworkMode::Http:
        stream.http.path = node_config.Path;
        stream.http.host = node_config.Host;
        break;
    case NetworkMode::Grpc:
        stream.grpc.service_name = node_config.ServiceName;
        stream.grpc.authority = node_config.Host;
        break;
    case NetworkMode::XHttp:
        stream.xhttp.path = node_config.Path;
        stream.xhttp.host = node_config.Host;
        break;
    default:
        break;
    }

    stream = NormalizeStreamSettings(stream);
    if (stream.network_mode == NetworkMode::Unsupported ||
        stream.security_mode == SecurityMode::Unsupported) {
        throw std::invalid_argument("panel inbound has unsupported stream settings");
    }
    return stream;
}

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

}  // namespace

std::vector<InboundUserSpec> MapPanelUsers(
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users) {
    std::vector<InboundUserSpec> specs;
    specs.reserve(users.size());
    for (const auto& user : users) {
        specs.push_back(InboundUserSpec{
            .user_id = user.UID,
            .email = user.Email,
            .credential = user.UUID,
            .flow = user.Flow.empty() ? node_config.Flow : user.Flow,
            .speed_limit = user.SpeedLimit,
            .device_limit = user.DeviceLimit,
        });
    }
    return specs;
}

InboundSpec MapPanelInbound(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users) {
    const int node_id = panel_config.NodeIDs.Front();
    std::string tag = naming::BuildPanelNodeTag(
        panel_config.Name, node_id, node_config.NodeType, node_config.Port);
    std::vector<std::string> all_tags{tag, std::string(constants::protocol::kNode)};
    routing::OutboundSelectionPolicy outbound_policy{routing::RouteWithFallback(tag)};
    return InboundSpec{
        .tag = std::move(tag),
        .all_tags = std::move(all_tags),
        .accounting_key = naming::BuildPanelNodeAccountingKey(panel_config.Name, node_id),
        .protocol = node_config.NodeType,
        .listen = panel_config.ListenIP,
        .port = node_config.Port,
        .proxy_protocol = panel_config.ProxyProtocol,
        .settings = InboundProtocolSettings{
            .method = node_config.CypherMethod,
            .identity_password = node_config.ShadowsocksServerKey,
            .ss2022_user_key = Ss2022UserKey::UuidDerived,
            .padding_scheme = node_config.PaddingScheme,
            .vless_decryption = std::string(constants::protocol::kNone),
            .hysteria_up_mbps = node_config.HysteriaUpMbps,
            .hysteria_down_mbps = node_config.HysteriaDownMbps,
        },
        .users = MapPanelUsers(node_config, users),
        .stream_settings = MapPanelStreamSettings(panel_config, node_config),
        .sniffing = SniffConfig{},
        .outbound_policy = std::move(outbound_policy),
    };
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
    failed_ = true;
}
void TrafficJournal::SyncDirectory() {
    if (::fsync(directory_fd_) != 0) SystemFailure("sync traffic journal directory");
}
void TrafficJournal::Append(const app::UserTrafficSnapshot& traffic) {
    if (traffic.empty()) return;
    CheckHealthy();
    constexpr uint64_t max_value = static_cast<uint64_t>(INT64_MAX);
    json::array rows;
    for (const auto& [uid, value] : traffic.users) {
        if (uid <= 0 || value.upload > max_value || value.download > max_value) {
            throw std::runtime_error("traffic exceeds UniProxy signed integer range");
        }
        if (value.upload == 0 && value.download == 0) continue;
        rows.push_back(json::array{uid, value.upload, value.download});
    }
    if (rows.empty()) return;
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
        if (entry.path().extension() == ".unknown") ++count;
    }
    return count;
}

}  // namespace controller

struct Controller::Impl : std::enable_shared_from_this<Controller::Impl> {
    struct PanelRuntime;
    class NodeRuntime;
    Impl(net::io_context& io_context,
         const std::vector<std::unique_ptr<Worker>>& workers);

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();
    net::awaitable<void> FlushTraffic();
    void ThrowIfStopping() const;

    [[nodiscard]] std::vector<Controller::NodeStatsInfo> GetNodeStats() const;

    net::awaitable<void> panelSyncLoop(PanelRuntime& panel);
    net::awaitable<void> panelStatusLoop(const PanelRuntime& panel) const;
    net::awaitable<void> nodeInfoMonitor(PanelRuntime& panel);
    void logPanelStatus(const PanelRuntime& panel) const;
    net::awaitable<void> userInfoMonitor(PanelRuntime& panel,
                                         std::string tag);

    net::awaitable<bool> collectTraffic(PanelRuntime& panel,
                                        bool* appended_out = nullptr);
    net::awaitable<controller::OnlineSnapshot>
    GetOnlineSnapshot(const std::string& tag);

    net::io_context&                       io_context_;
    const std::vector<std::unique_ptr<Worker>>&  workers_;
    bool stopping_ = false;
    controller::NodeMutationGate node_mutations_;
    std::unique_ptr<controller::JournalExecutor> journal_executor_;

    enum class PanelState {
        Connecting,
        Ready,
        Degraded,
        Unavailable,
    };

    struct NodeStats {
        size_t   online_count = 0;
        uint64_t bytes_up     = 0;
        uint64_t bytes_down   = 0;
    };
    struct PanelRuntime {
        PanelRuntime(std::unique_ptr<api::API> api, const PanelConfig& source,
                     controller::NodeMutationGate& gate, net::any_io_executor executor);

        const std::unique_ptr<api::API> client;
        const PanelConfig config;
        const int node_id;
        const PanelLogContext log_context;
        const std::string accounting_key;
        PanelState state = PanelState::Connecting;
        controller::NodeState node;
        controller::NodeMutationGate::Participant mutation;
        NodeStats stats;
        std::unique_ptr<controller::TrafficJournal> traffic_journal;
        // Active loops retain Impl, which owns these address-stable entities.
        std::weak_ptr<monitor_detail::MonitorLoop> sync_loop;
        std::weak_ptr<monitor_detail::MonitorLoop> status_loop;
    };
    std::vector<std::unique_ptr<PanelRuntime>> panels_;
};
namespace {

[[nodiscard]] std::string_view DomainStrategyName(
    proxy::freedom::outbound::DomainStrategy strategy) noexcept {
    using proxy::freedom::outbound::DomainStrategy;
    switch (strategy) {
        case DomainStrategy::AsIs: return "AsIs";
        case DomainStrategy::UseIP: return "UseIP";
        case DomainStrategy::UseIPv6v4: return "UseIPv6v4";
        case DomainStrategy::UseIPv4: return "UseIPv4";
        case DomainStrategy::UseIPv4v6: return "UseIPv4v6";
        case DomainStrategy::UseIPv6: return "UseIPv6";
        case DomainStrategy::ForceIP: return "ForceIP";
        case DomainStrategy::ForceIPv6v4: return "ForceIPv6v4";
        case DomainStrategy::ForceIPv6: return "ForceIPv6";
        case DomainStrategy::ForceIPv4v6: return "ForceIPv4v6";
        case DomainStrategy::ForceIPv4: return "ForceIPv4";
    }
    return "AsIs";
}

[[nodiscard]] proxyman::outbound::PreparedOutboundConfig BuildPanelAutoOutbound(
    const std::string& tag,
    const PanelConfig& panel_config) {
    const auto strategy = panel_config.EnableDNS
        ? panel_config.DNSType
        : proxy::freedom::outbound::DomainStrategy::AsIs;
    infra::OutboundSourceConfig source{
        .tag = tag,
        .protocol = std::string(constants::protocol::kFreedom),
        .settings = json::object{{"domainStrategy", DomainStrategyName(strategy)}},
        .stream_settings = {},
        // The panel sendIP is the auto outbound Handler's sendThrough.
        .send_through = panel_config.SendIP,
        .passthrough = false,
    };
    auto prepared = proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared) {
        throw std::logic_error("failed to prepare panel auto freedom outbound");
    }
    return std::move(*prepared);
}

std::unique_ptr<api::API> ValidatePanelRuntimeArgs(
    std::unique_ptr<api::API> api, const PanelConfig& source) {
    if (!api || source.Name.empty() || source.NodeIDs.Values().size() != 1) {
        throw std::invalid_argument("panel runtime requires a client, a name and one node ID");
    }
    return api;
}

[[nodiscard]] std::string_view ResolvedNodeNetwork(
    const controller::NodeSnapshot& state) noexcept {
    if (state.inbound) {
        return state.inbound->receiver.stream_settings.network;
    }
    return state.config.TransportProtocol.empty()
        ? constants::protocol::kTcp
        : std::string_view(state.config.TransportProtocol);
}


template <typename WorkerRange, typename TaskFactory>
net::awaitable<void> RunWorkerMutationBatch(
    net::any_io_executor executor,
    WorkerRange& workers,
    TaskFactory task_factory) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers.size());
    for (size_t i = 0; i < workers.size(); ++i) {
        tasks.push_back(task_factory(*workers[i], i));
    }
    co_await RunAwaitableBatch(executor, std::move(tasks));
}
}  // namespace

// The concrete cold-path boundary for all-Worker mutations. Each asynchronous
// operation joins every started Worker task before it completes or throws.
class Controller::Impl::NodeRuntime {
public:
    NodeRuntime(net::io_context& io_context,
                const std::vector<std::unique_ptr<Worker>>& workers,
                PanelRuntime& panel,
                const bool& stopping)
        : io_context_(io_context), workers_(workers), panel_(panel),
          stopping_(stopping) {}

    net::awaitable<void> RemoveInbound(const std::string& tag) {
        ThrowIfStopping();
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [this, tag](Worker& worker, size_t) {
                return [](NodeRuntime* runtime, Worker* current, std::string current_tag)
                           -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    co_await current->PostTask(
                        current->UnregisterListenerTask(std::move(current_tag)));
                }(this, &worker, tag);
            });
    }

    net::awaitable<void> RemoveOutbound(const std::string& tag) {
        ThrowIfStopping();
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [this, tag](Worker& worker, size_t) {
                return [](NodeRuntime* runtime, Worker* current, std::string current_tag)
                           -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    co_await current->PostCall([current, tag = std::move(current_tag)] {
                        current->RemoveOutbound(tag);
                    });
                }(this, &worker, tag);
            });
    }

    net::awaitable<void> AddOutbound(
        const proxyman::outbound::PreparedOutboundConfig& prepared) {
        ThrowIfStopping();
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [this, &prepared](Worker& worker, size_t) {
                return [](NodeRuntime* runtime, Worker* current,
                          proxyman::outbound::PreparedOutboundConfig config)
                           -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    co_await current->PostCall([current, config = std::move(config)]() mutable {
                        current->AddOutbound(std::move(config));
                    });
                }(this, &worker, prepared);
            });
    }

    net::awaitable<bool> AddInbound(const PreparedInbound& inbound) {
        ThrowIfStopping();
        const auto& log_context = panel_.log_context;
        const auto& tag = inbound.binding.tag;

        std::exception_ptr publish_failure;
        try {
            std::vector<InboundInstallFailure> installed(
                workers_.size(), InboundInstallFailure::None);
            for (size_t index = 0; index < workers_.size(); ++index) {
                ThrowIfStopping();
                installed[index] = co_await workers_[index]->PostTask(
                    InstallInbound(*workers_[index], inbound));
            }

            const auto failed = std::ranges::find_if(
                installed, [](InboundInstallFailure result) {
                    return result != InboundInstallFailure::None;
                });
            if (failed != installed.end()) {
                LOG_PANEL_WARN(log_context, "Inbound install failed: stage={} protocol={} tag={}",
                         InboundInstallFailureName(*failed), inbound.binding.protocol, tag);
                co_await RemoveInbound(tag);
                co_return false;
            }
        } catch (...) {
            publish_failure = std::current_exception();
        }

        if (publish_failure) {
            if (IsStopping()) std::rethrow_exception(publish_failure);
            try {
                co_await RemoveInbound(tag);
            } catch (const std::exception& cleanup_error) {
                LOG_PANEL_ERROR(log_context, "Inbound cleanup after publish failure failed: {}", cleanup_error.what());
            } catch (...) {
                LOG_PANEL_ERROR(log_context, "Inbound cleanup after publish failure failed: unknown exception");
            }
            std::rethrow_exception(publish_failure);
        }
        ThrowIfStopping();

        LOG_PANEL_INFO(log_context, "inbound ready: tag={} port={} protocol={} network={} workers={} accept=SO_REUSEPORT",
                       tag, inbound.binding.port, inbound.binding.protocol,
                       inbound.receiver.stream_settings.network, workers_.size());
        co_return true;
    }

    net::awaitable<void> UpdateRules(
        const std::string& tag,
        std::shared_ptr<const std::vector<rule::DetectRule>> new_rule_list) {
        ThrowIfStopping();
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [this, &tag, &new_rule_list](Worker& worker, size_t index) {
                return [](NodeRuntime* runtime, Worker* current,
                          std::string current_tag,
                          std::shared_ptr<const std::vector<rule::DetectRule>> rules) -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    co_await current->PostCall(
                        [current, tag = std::move(current_tag), rules = std::move(rules)]() mutable {
                            current->UpdateRule(tag, std::move(rules));
                        });
                }(this, &worker, tag,
                  index + 1 == workers_.size() ? std::move(new_rule_list) : new_rule_list);
            });
    }

    net::awaitable<void> RecoverUsers() {
        co_await ::RollbackUsers(
            io_context_.get_executor(), workers_, panel_.node.user_recovery, stopping_);
    }

    net::awaitable<void> ClearUsers(const std::string& tag, const std::string& protocol) {
        co_await RecoverUsers();
        const auto user_protocol = proxyman::inbound::RegisteredUserProtocol(protocol);
        if (!user_protocol) throw std::logic_error("node has no registered user protocol");
        co_await ::PublishUsers(io_context_.get_executor(), workers_,
            proxyman::inbound::UserStore::PrepareClearUsers(*user_protocol, tag),
            panel_.node.user_recovery, stopping_);
    }

    net::awaitable<void> ApplyUsers(
        const std::string& tag, const proxyman::inbound::UserSet& users) {
        co_await RecoverUsers();
        co_await ::PublishUsers(io_context_.get_executor(), workers_,
            proxyman::inbound::UserStore::PrepareUsers(tag, users),
            panel_.node.user_recovery, stopping_);
    }

    [[nodiscard]] bool IsStopping() const noexcept { return stopping_; }

private:
    void ThrowIfStopping() const {
        if (stopping_) throw IoSystemError(net::error::operation_aborted);
    }
    net::io_context& io_context_;
    const std::vector<std::unique_ptr<Worker>>& workers_;
    PanelRuntime& panel_;
    const bool& stopping_;
};
Controller::Controller(net::io_context& io_context,
                       const std::vector<std::unique_ptr<Worker>>& workers)
    : impl_(std::make_shared<Impl>(io_context, workers)) {}

Controller::~Controller() = default;

void Controller::AddPanel(std::unique_ptr<api::API> panel,
                          const PanelConfig& panel_config) {
    impl_->AddPanel(std::move(panel), panel_config);
}

void Controller::Start() {
    impl_->Start();
}

void Controller::RequestStop() noexcept {
    impl_->RequestStop();
}

net::awaitable<void> Controller::AsyncJoin() {
    co_await impl_->AsyncJoin();
}

net::awaitable<void> Controller::FlushTraffic() {
    co_await impl_->FlushTraffic();
}

std::vector<Controller::NodeStatsInfo> Controller::GetNodeStats() const {
    return impl_->GetNodeStats();
}

Controller::Impl::Impl(net::io_context& io_context,
                       const std::vector<std::unique_ptr<Worker>>& workers)
    : io_context_(io_context)
    , workers_(workers) {}

Controller::Impl::PanelRuntime::PanelRuntime(
    std::unique_ptr<api::API> api, const PanelConfig& source,
    controller::NodeMutationGate& gate, net::any_io_executor executor)
    : client(ValidatePanelRuntimeArgs(std::move(api), source))
    , config(source)
    , node_id(config.NodeIDs.Front())
    , log_context{config.Name, config.APIHost, node_id, config.NodeType}
    , accounting_key(naming::BuildPanelNodeAccountingKey(config.Name, node_id))
    , mutation(gate, std::move(executor), node) {
    traffic_journal = std::make_unique<controller::TrafficJournal>(config);
    const auto unknown = traffic_journal->UnknownCount();
    if (unknown != 0) {
        LOG_PANEL_ERROR(log_context, "Traffic accounting requires reconciliation: unknown_records={} directory={}",
                        unknown, traffic_journal->Directory().string());
    }
}

void Controller::Impl::AddPanel(std::unique_ptr<api::API> panel,
                                const PanelConfig& panel_config) {
    ThrowIfStopping();
    // Construct the complete entity before publishing it to the owner.
    auto runtime = std::make_unique<PanelRuntime>(
        std::move(panel), panel_config, node_mutations_, io_context_.get_executor());
    if (!journal_executor_) {
        journal_executor_ = std::make_unique<controller::JournalExecutor>();
    }
    panels_.push_back(std::move(runtime));
}

void Controller::Impl::Start() {
    if (stopping_) return;
    node_mutations_.Seal();
    enum class LoopKind { Sync, Status };
    for (auto& entry : panels_) {
        auto* panel = entry.get();
        for (const auto kind : {LoopKind::Sync, LoopKind::Status}) {
            auto& slot = kind == LoopKind::Sync ? panel->sync_loop : panel->status_loop;
            if (!slot.expired()) continue;
            const auto name = std::format("{}/{} {}",
                panel->config.Name, panel->node_id,
                kind == LoopKind::Sync ? "sync" : "status");
            auto self = shared_from_this();
            auto loop = std::make_shared<monitor_detail::MonitorLoop>(
                io_context_.get_executor(), name,
                [self, panel, kind] {
                    return kind == LoopKind::Sync
                        ? self->panelSyncLoop(*panel) : self->panelStatusLoop(*panel);
                },
                [self, panel, kind](std::string_view loop_name, std::exception_ptr failure) {
                    if (self->stopping_ && !failure) return;
                    if (kind == LoopKind::Sync) {
                        panel->state = PanelState::Unavailable;
                    }
                    if (!failure) {
                        LOG_PANEL_WARN(panel->log_context, "Panel monitor stopped unexpectedly: loop={}", loop_name);
                        return;
                    }
                    try {
                        std::rethrow_exception(failure);
                    } catch (const std::exception& error) {
                        LOG_PANEL_ERROR(panel->log_context, "Panel monitor failed: loop={} reason={}", loop_name, error.what());
                    } catch (...) {
                        LOG_PANEL_ERROR(panel->log_context, "Panel monitor failed: loop={} reason=unknown exception", loop_name);
                    }
                });
            slot = loop;
            loop->Start();
        }
    }
}

void Controller::Impl::RequestStop() noexcept {
    if (stopping_) return;
    stopping_ = true;
    node_mutations_.Close();
    for (const auto& panel : panels_) {
        if (auto loop = panel->sync_loop.lock()) loop->RequestStop();
        if (auto loop = panel->status_loop.lock()) loop->RequestStop();
    }
}

net::awaitable<void> Controller::Impl::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    for (const auto& panel : panels_) {
        if (auto loop = panel->sync_loop.lock()) co_await loop->AsyncJoin();
        if (auto loop = panel->status_loop.lock()) co_await loop->AsyncJoin();
    }
}

void Controller::Impl::ThrowIfStopping() const {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
}

std::vector<Controller::NodeStatsInfo> Controller::Impl::GetNodeStats() const {
    std::vector<NodeStatsInfo> result;
    result.reserve(panels_.size());
    for (const auto& panel : panels_) {
        if (!panel->node.committed ||
            panel->node.phase != controller::NodeRuntimePhase::Ready) {
            continue;
        }
        const auto& state = *panel->node.committed;

        NodeStatsInfo info;
        info.panel_name  = panel->config.Name;
        info.panel_host  = panel->config.APIHost;
        info.node_type   = panel->config.NodeType;
        info.node_id     = panel->node_id;
        info.network      = std::string(ResolvedNodeNetwork(state));
        info.port       = state.config.Port;
        info.total_users  = state.users ? state.users->size() : 0;
        info.online_users = panel->stats.online_count;
        info.bytes_up     = panel->stats.bytes_up;
        info.bytes_down   = panel->stats.bytes_down;
        result.push_back(std::move(info));
    }
    return result;
}

net::awaitable<void> Controller::Impl::panelSyncLoop(
    PanelRuntime& panel) {
    using Clock = std::chrono::steady_clock;
    const auto& log_context = panel.log_context;
    auto next_pull = Clock::now();
    // Match v2node reporting semantics: the first traffic/online snapshot
    // needs one complete push interval to accumulate meaningful activity.
    auto next_push = Clock::time_point::max();
    net::steady_timer timer(io_context_);

    const auto interval = [&](bool pull) {
        if (panel.node.committed) {
            return pull
                ? controller::PanelInterval(
                      panel.node.committed->config.PullInterval,
                      defaults::kPanelPullInterval)
                : controller::PanelInterval(
                      panel.node.committed->config.PushInterval,
                      defaults::kPanelPushInterval);
        }
        return std::chrono::seconds(
            pull ? defaults::kPanelPullInterval
                 : defaults::kPanelPushInterval);
    };

    for (;;) {
        if (stopping_) co_return;
        auto now = Clock::now();
        if (now >= next_pull) {
            try {
                co_await nodeInfoMonitor(panel);
            } catch (const std::exception& e) {
                if (stopping_) throw;
                panel.state = PanelState::Unavailable;
                LOG_PANEL_ERROR(log_context, "Panel sync unavailable: operation=pull reason={}", e.what());
                if (panel.node.HasPendingCleanup()) {
                    LOG_PANEL_ERROR(log_context, "Panel sync requires recovery: pending runtime cleanup");
                }
            } catch (...) {
                if (stopping_) throw;
                panel.state = PanelState::Unavailable;
                LOG_PANEL_ERROR(log_context, "Panel sync unavailable: operation=pull reason=unknown error");
                if (panel.node.HasPendingCleanup()) {
                    LOG_PANEL_ERROR(log_context, "Panel sync requires recovery: pending runtime cleanup");
                }
            }
            now = Clock::now();
            const auto pull_delay = panel.node.HasPendingCleanup()
                ? std::min(interval(true), std::chrono::seconds(1))
                : interval(true);
            next_pull = now + pull_delay;
            if (panel.node.committed && panel.node.phase == controller::NodeRuntimePhase::Ready) {
                const auto scheduled_push = now + interval(false);
                if (next_push == Clock::time_point::max()) {
                    next_push = scheduled_push;
                } else {
                    next_push = std::min(next_push, scheduled_push);
                }
            } else {
                next_push = Clock::time_point::max();
            }
        }

        if (stopping_) co_return;
        now = Clock::now();
        if (now >= next_push) {
            if (panel.node.committed && panel.node.phase == controller::NodeRuntimePhase::Ready) {
                try {
                    co_await userInfoMonitor(panel, panel.node.committed->tag);
                } catch (const std::exception& e) {
                    if (stopping_) throw;
                    LOG_PANEL_WARN(log_context, "Panel report unavailable: operation=push reason={}", e.what());
                } catch (...) {
                    if (stopping_) throw;
                    LOG_PANEL_WARN(log_context, "Panel report unavailable: operation=push reason=unknown error");
                }
            }
            next_push = Clock::now() + interval(false);
        }

        timer.expires_at(std::min(next_pull, next_push));
        co_await timer.async_wait(net::use_awaitable);
    }
}

net::awaitable<void> Controller::Impl::panelStatusLoop(const PanelRuntime& panel) const {
    using Clock = std::chrono::steady_clock;
    constexpr auto interval = std::chrono::seconds(defaults::kPanelStatusLogInterval);
    auto next_status = Clock::now();
    net::steady_timer timer(io_context_);
    for (;;) {
        if (stopping_) co_return;
        // Read the last committed state on the controller executor. No snapshot
        // reference crosses the wait, and no network request delays this loop.
        logPanelStatus(panel);
        next_status += interval;
        const auto now = Clock::now();
        if (next_status <= now) {
            // Keep the fixed cadence without emitting a burst for missed ticks.
            next_status += interval * ((now - next_status) / interval + 1);
        }
        timer.expires_at(next_status);
        co_await timer.async_wait(net::use_awaitable);
    }
}

net::awaitable<void> Controller::Impl::nodeInfoMonitor(PanelRuntime& panel) {
    const int node_id = panel.node_id;
    const auto& panel_name = panel.config.Name;
    const auto& log_context = panel.log_context;

    NodeRuntime runtime(io_context_, workers_, panel, stopping_);

    // One pull attempt is made for each scheduler invocation.
    // Cleanup depends only on retained local snapshots, so a failing or
    // unavailable panel cannot indefinitely retain orphan resources.
    if (panel.node.HasPendingCleanup()) {
        auto lease = co_await node_mutations_.Acquire(panel.mutation);
        ThrowIfStopping();
        co_await controller::CleanPendingNodeRuntime(runtime, panel.node);
    }
    ThrowIfStopping();
    const auto old_state = panel.node.committed;
    auto config_result = co_await panel.client->GetNodeInfo(
        old_state ? old_state->config_etag : std::string{});
    ThrowIfStopping();
    if (!config_result.Ok()) {
        throw std::runtime_error(ErrorMessage(config_result.error, config_result.error_msg));
    }

    if (config_result.not_modified && !old_state) {
        throw std::runtime_error("node not modified without a committed snapshot");
    }
    const api::NodeInfo& fetched_config = config_result.not_modified
        ? old_state->config : *config_result.node_info;
    const std::string& protocol = fetched_config.NodeType;
    const std::string tag = naming::BuildPanelNodeTag(
        panel_name, node_id, protocol, fetched_config.Port);

    const api::NodeInfo* old_config =
        old_state ? &old_state->config : nullptr;
    const bool old_started = panel.node.phase == controller::NodeRuntimePhase::Ready;
    const auto transition = controller::PlanNodeTransition(
        old_config,
        old_started,
        fetched_config);
    const bool transitioning = transition.Transitioning();

    if (transition.mode == controller::NodeTransitionMode::StageNewEndpoint
        || transition.mode == controller::NodeTransitionMode::ReplaceInPlace
        || transition.mode == controller::NodeTransitionMode::SwapSameEndpoint) {
        LOG_PANEL_INFO(log_context, "Panel configuration changed; recreating inbound");
    }

    const bool replace_rules = !config_result.not_modified || transitioning;

    auto users_result = co_await panel.client->GetUserList(
        old_state ? old_state->users_etag : std::string{});
    ThrowIfStopping();
    std::optional<std::vector<api::UserInfo>> next_users;
    if (!users_result.Ok()) {
        if (transitioning) {
            throw std::runtime_error(ErrorMessage(
                users_result.error, users_result.error_msg));
        }
        LOG_PANEL_WARN(log_context, "Panel sync degraded: operation=pull resource=users reason={}",
                 users_result.error_msg.empty()
                    ? ErrorCodeToString(users_result.error)
                    : users_result.error_msg);
    } else if (users_result.not_modified) {
        if (!old_state) {
            throw std::runtime_error(
                "panel returned users not modified without a committed user snapshot");
        }
    } else {
        next_users = std::move(users_result.users);
    }

    if (!transitioning && config_result.not_modified && !next_users) {
        panel.state = users_result.Ok() ? PanelState::Ready : PanelState::Degraded;
        co_return;
    }
    auto candidate = std::make_shared<controller::NodeSnapshot>();
    candidate->config = config_result.not_modified
        ? old_state->config : std::move(*config_result.node_info);
    candidate->config_etag = config_result.not_modified
        ? old_state->config_etag : std::move(config_result.etag);
    candidate->tag = tag;
    candidate->users = next_users
        ? std::make_shared<const std::vector<api::UserInfo>>(std::move(*next_users))
        : old_state->users;
    candidate->users_etag = next_users
        ? std::move(users_result.etag) : old_state->users_etag;
    candidate->rules = config_result.not_modified
        ? old_state->rules
        : std::make_shared<const std::vector<rule::DetectRule>>(
              std::move(config_result.rules));
    const bool rebuild_settings = !old_state ||
        controller::NodeConfigChanged(old_state->config, candidate->config);
    if (rebuild_settings) {
        candidate->inbound = std::make_shared<const PreparedInbound>(PrepareInbound(
            controller::MapPanelInbound(panel.config, candidate->config, *candidate->users)));
        candidate->outbound =
            std::make_shared<const proxyman::outbound::PreparedOutboundConfig>(
                BuildPanelAutoOutbound(tag, panel.config));
    } else if (next_users) {
        // Only the users changed: keep every prepared setting and rebuild the
        // authentication payload through the same per-protocol builder.
        auto inbound = std::make_shared<PreparedInbound>(*old_state->inbound);
        inbound->users = PrepareInboundUsers(
            inbound->build_request,
            controller::MapPanelUsers(candidate->config, *candidate->users));
        candidate->inbound = std::move(inbound);
        candidate->outbound = old_state->outbound;
    } else {
        candidate->inbound = old_state->inbound;
        candidate->outbound = old_state->outbound;
    }
    controller::PreparedNodeChange change;
    change.replace_users = next_users.has_value() || transitioning;
    change.replace_rules = replace_rules;
    change.next = std::move(candidate);
    // Candidate data and authentication payloads are complete before
    // entering the transaction's first runtime mutation.
    // Hold fair admission before checking endpoints: another panel may
    // commit or retain recovery reservations while this one waits.
    auto lease = co_await node_mutations_.Acquire(panel.mutation);
    ThrowIfStopping();
    if (panel.node.HasPendingCleanup()) {
        throw std::logic_error("node admission requires completed local cleanup");
    }
    for (const auto& other : panels_) {
        if (other.get() != &panel && other->node.ReservesPort(change.next->config.Port) &&
            other->config.ListenIP.Overlaps(panel.config.ListenIP)) {
            throw std::runtime_error(std::format(
                "panel listener endpoint conflict owner={}/{} port={}",
                other->config.Name, other->node_id, change.next->config.Port));
        }
    }
    co_await controller::ApplyNodeChange(runtime, panel.node, std::move(change));
    ThrowIfStopping();
    if (transitioning) {
        LOG_PANEL_INFO(log_context, "Panel configuration ready: tag={} replaced={}",
            tag, old_state ? "yes" : "no");
    }
    panel.state = users_result.Ok() ? PanelState::Ready : PanelState::Degraded;
}

void Controller::Impl::logPanelStatus(const PanelRuntime& panel) const {
    const auto& log_context = panel.log_context;
    const std::string_view state_text = [&]() -> std::string_view {
        switch (panel.state) {
            case PanelState::Connecting: return "connecting";
            case PanelState::Ready: return "ready";
            case PanelState::Degraded: return "degraded";
            case PanelState::Unavailable: return "unavailable";
        }
        return "unavailable";
    }();
    const std::string_view runtime_text = [&]() -> std::string_view {
        switch (panel.node.phase) {
            case controller::NodeRuntimePhase::Stopped: return "stopped";
            case controller::NodeRuntimePhase::Ready: return "ready";
            case controller::NodeRuntimePhase::Updating: return "updating";
            case controller::NodeRuntimePhase::RecoveryRequired: return "recovery required";
        }
        return "recovery required";
    }();

    if (!panel.node.committed) {
        LOG_PANEL_INFO(log_context, "Panel status: state={} inbound={} protocol={}",
            state_text, runtime_text, panel.config.NodeType);
        return;
    }

    const auto& committed_state = *panel.node.committed;
    const auto& protocol = committed_state.config.NodeType;
    const auto pull_interval = controller::PanelInterval(
        committed_state.config.PullInterval,
        defaults::kPanelPullInterval);
    const auto push_interval = controller::PanelInterval(
        committed_state.config.PushInterval,
        defaults::kPanelPushInterval);
    LOG_PANEL_INFO(log_context,
        "Panel status: state={} inbound={} protocol={} port={} network={} users={} rules={} pull={}s push={}s",
        state_text,
        runtime_text,
        protocol,
        committed_state.config.Port,
        ResolvedNodeNetwork(committed_state),
        committed_state.users ? committed_state.users->size() : 0,
        committed_state.rules ? committed_state.rules->size() : 0,
        pull_interval.count(),
        push_interval.count());
}

net::awaitable<bool>
Controller::Impl::collectTraffic(PanelRuntime& panel, bool* appended_out) {
    // Do not abandon a durable append before its matching Worker commit.
    // Shutdown joins this critical section before taking its final snapshot.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    // Only this panel loop may snapshot/commit its accounting key. The disk
    // executor never touches Worker-owned state and has bounded admission.
    bool appended = false;
    for (const auto& worker : workers_) {
        auto* w = worker.get();
        auto snapshot = co_await w->PostCall([w, &panel] {
            return w->SnapshotTraffic(panel.accounting_key);
        });
        if (snapshot.empty()) continue;
        std::exception_ptr append_failure;
        try {
            co_await journal_executor_->Run([&panel, &snapshot] {
                panel.traffic_journal->Append(snapshot);
                return true;
            });
        } catch (...) {
            append_failure = std::current_exception();
        }
        if (append_failure) {
            // The snapshot token may be the last owner after a connection has
            // closed. Return it to the Worker ledger before unwinding.
            try {
                co_await w->PostCall([w, &panel, &snapshot] {
                    w->RollbackTraffic(panel.accounting_key, snapshot);
                });
            } catch (...) {
                panel.traffic_journal->Suspend();
                throw;
            }
            std::rethrow_exception(append_failure);
        }
        appended = true;
        if (appended_out) *appended_out = true;
        // A successful append is durable. A failed commit must suspend further
        // collection, otherwise the same in-memory delta could be persisted twice.
        try {
            co_await w->PostCall([w, &panel, &snapshot] {
                w->CommitTraffic(panel.accounting_key, snapshot);
            });
        } catch (...) {
            panel.traffic_journal->Suspend();
            throw;
        }
    }
    co_return appended;
}

net::awaitable<void> Controller::Impl::FlushTraffic() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    std::exception_ptr failure;
    for (const auto& panel : panels_) {
        try {
            co_await collectTraffic(*panel);
        } catch (const std::exception& error) {
            if (!failure) failure = std::current_exception();
            LOG_PANEL_ERROR(panel->log_context, "Final traffic persistence failed: {}", error.what());
        } catch (...) {
            if (!failure) failure = std::current_exception();
            LOG_PANEL_ERROR(panel->log_context, "Final traffic persistence failed: unknown error");
        }
    }
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<controller::OnlineSnapshot>
Controller::Impl::GetOnlineSnapshot(const std::string& tag) {
    ThrowIfStopping();
    std::vector<std::vector<OnlineDevice>> per_worker(workers_.size());

    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, &tag, &per_worker](Worker& worker, size_t index) {
            return [](Impl* controller, Worker* w, std::string_view t,
                      std::vector<OnlineDevice>& out) -> net::awaitable<void> {
                controller->ThrowIfStopping();
                out = co_await w->PostCall([w, t] {
                    return w->GetOnlineDevices(t);
                });
            }(this, &worker, tag, per_worker[index]);
        });
    ThrowIfStopping();

    size_t total_online = 0;
    for (const auto& online : per_worker) {
        total_online += online.size();
    }

    std::vector<OnlineDevice> devices;
    devices.reserve(total_online);
    for (auto& online : per_worker) {
        devices.insert(devices.end(),
                       std::make_move_iterator(online.begin()),
                       std::make_move_iterator(online.end()));
    }
    co_return controller::BuildOnlineSnapshot(std::move(devices));
}

net::awaitable<void> Controller::Impl::userInfoMonitor(PanelRuntime& panel,
                                                       std::string tag) {
    const auto& log_context = panel.log_context;

    ThrowIfStopping();
    // Drain never-attempted crash/backpressure records before collecting more;
    // otherwise a full journal of ready records could never free its capacity.
    auto& ns = panel.stats;
    controller::TrafficJournal::Batch batch;
    bool traffic_ok = false;
    bool journal_ok = true;
    try {
        batch = co_await journal_executor_->Run([&panel] {
            return panel.traffic_journal->Prepare();
        });
        if (batch.records.empty()) {
            // reset_cancellation_state in collectTraffic applies to its entire
            // coroutine thread, not just that function. Join a shielded child so a
            // durable append always reaches CommitTraffic without disabling stop
            // cancellation for this loop's subsequent panel requests.
            bool appended = false;
            try {
                co_await net::co_spawn(io_context_,
                    collectTraffic(panel, &appended),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
            } catch (const std::exception& e) {
                if (stopping_) throw;
                journal_ok = false;
                LOG_PANEL_WARN(log_context, "Traffic collection failed: operation=push reason={}", e.what());
            }
            ThrowIfStopping();
            if (appended) {
                batch = co_await journal_executor_->Run([&panel] {
                    return panel.traffic_journal->Prepare();
                });
            }
        }
        ThrowIfStopping();
        if (!batch.records.empty()) {
            co_await journal_executor_->Run([&panel, &batch] {
                panel.traffic_journal->Begin(batch);
                return true;
            });
        }
        const auto& traffic_data = batch.traffic;
        uint64_t batch_up = 0;
        uint64_t batch_down = 0;
        for (const auto& td : traffic_data) {
            batch_up += td.Upload;
            batch_down += td.Download;
        }
        if (!batch.records.empty() || journal_ok) {
            try {
                // Marked unknown durably BEFORE any network transmission. Even non-2xx
                // may follow partial server-side accounting; never retry these deltas.
                // An empty push still clears the panel's previous online-user count.
                traffic_ok = co_await panel.client->ReportUserTraffic(traffic_data);
            } catch (const std::exception& e) {
                if (stopping_) {
                    if (!traffic_ok && !batch.records.empty()) {
                        LOG_PANEL_ERROR(log_context, "Traffic accounting API acceptance unknown: records={} retained without retry; directory={}",
                                        batch.records.size(), panel.traffic_journal->Directory().string());
                    }
                    throw;
                }
                LOG_PANEL_WARN(log_context, "Traffic report failed: operation=push reason={}", e.what());
            }
        }
        if (!traffic_ok && !batch.records.empty()) {
            LOG_PANEL_ERROR(log_context, "Traffic accounting API acceptance unknown: records={} retained without retry; directory={}",
                            batch.records.size(), panel.traffic_journal->Directory().string());
        }
        if (traffic_ok) {
            ns.bytes_up += batch_up;
            ns.bytes_down += batch_down;
            if (!batch.records.empty()) {
                co_await journal_executor_->Run([&panel, &batch] {
                    panel.traffic_journal->Acknowledge(batch);
                    return true;
                });
            }
        }
        ThrowIfStopping();
        if (traffic_ok) {
            LOG_PANEL_DEBUG(log_context, "Traffic report accepted: users={}", traffic_data.size());
        }
    } catch (const std::exception& e) {
        if (stopping_) throw;
        journal_ok = false;
        LOG_PANEL_ERROR(log_context, "Traffic journal failed: operation=push reason={}", e.what());
    }

    auto online = co_await GetOnlineSnapshot(tag);
    ns.online_count = online.user_count;
    const auto& traffic_data = batch.traffic;

    ThrowIfStopping();
    bool online_ok = false;
    try {
        online_ok = co_await panel.client->ReportNodeOnlineUsers(online.entries);
        ThrowIfStopping();
    } catch (const std::exception& e) {
        if (stopping_) throw;
        LOG_PANEL_WARN(log_context, "Online report failed: operation=push reason={}", e.what());
    }

    const bool report_ok = traffic_ok && journal_ok && online_ok;
    LOG_PANEL_INFO(log_context,
        "Panel report: state={} operation=push traffic={} traffic_users={} online={} online_users={} devices={}",
        report_ok ? "ok" : "degraded",
        (traffic_ok && journal_ok) ? "ok" : "failed",
        traffic_data.size(),
        online_ok ? "ok" : "failed",
        online.user_count,
        online.entries.size());
    co_return;
}

