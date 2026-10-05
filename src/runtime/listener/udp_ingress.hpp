#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/link.hpp"

#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace acpp {
struct StatsShard;
struct TimeoutsConfig;

namespace routing {
class Dispatcher;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}
} // namespace acpp

namespace acpp::inbound_detail {

class UdpAssociationReclaimer;
struct UdpAssociationHook;

// All native UDP listeners in one Runtime share this owner-strand quota. It
// counts associations until their dispatcher coroutine has actually finished,
// including associations already removed from the routing table during stop.
class UdpAssociationQuota final {
public:
  static constexpr size_t kCapacity = 4096;

  [[nodiscard]] bool TryAcquire() noexcept {
    if (used_ >= kCapacity)
      return false;
    ++used_;
    return true;
  }

  void Release() noexcept {
    if (used_ != 0)
      --used_;
  }

  [[nodiscard]] size_t Used() const noexcept { return used_; }

private:
  size_t used_ = 0;
};

// Borrowed receive-loop input. ProcessDatagram consumes and owns every value it
// needs before returning. candidate_conn_id is allocated serially by Runtime;
// it is consumed only when this packet creates a new physical association.
struct UdpDatagramContext {
  std::string_view socket_key;
  udp::socket *socket = nullptr;
  udp::endpoint client_endpoint;
  std::span<const uint8_t> payload;
  const proxyman::inbound::ReceiverSettings *receiver = nullptr;
  routing::Dispatcher &dispatcher;
  TimeoutsConfig timeouts;
  uint64_t candidate_conn_id = 0;
  uint64_t runtime_generation = 1;
  uint64_t config_generation = 1;
};

// Listener-strand owner for one native UDP inbound. Protocol decoding, the
// socket table and reply sends stay on the listener strand. Every association
// receives its own strand and communicates with this owner through bounded,
// value-owning messages.
class UdpIngress final : public memory::DataAllocated {
public:
  using SocketPtr = std::shared_ptr<udp::socket>;

  struct ResourceStats {
    size_t associations = 0;
    size_t retiring_associations = 0;
    uint64_t input_datagrams = 0;
    uint64_t input_bytes = 0;
    uint64_t reply_datagrams = 0;
    uint64_t reply_bytes = 0;
    size_t active_reply_senders = 0;
    size_t native_dispatches = 0;
    uint64_t association_drops = 0;
    uint64_t message_drops = 0;
  };

  UdpIngress(std::string tag, std::unique_ptr<::acpp::Inbound> proxy,
             UdpAssociationReclaimer &reclaimer, UdpAssociationQuota &quota,
             net::any_io_executor listener_executor,
             net::any_io_executor runtime_executor,
             StatsShard &aggregate_stats);
  ~UdpIngress() noexcept;

  UdpIngress(const UdpIngress &) = delete;
  UdpIngress &operator=(const UdpIngress &) = delete;

  [[nodiscard]] std::string_view Tag() const noexcept;
  [[nodiscard]] ResourceStats GetResourceStats() const noexcept;
  [[nodiscard]] net::any_io_executor Executor() const;

  [[nodiscard]] bool
  ReplaceHandler(std::unique_ptr<::acpp::Inbound> proxy) noexcept;

  void RequestStop() noexcept;
  [[nodiscard]] net::awaitable<void> AsyncJoin();

  // Returns true only when candidate_conn_id was committed to a newly
  // started association. Runtime advances its physical-ID sequence then.
  [[nodiscard]] bool ProcessDatagram(const UdpDatagramContext &datagram);

  [[nodiscard]] static SocketPtr MakeSocket(net::any_io_executor executor) {
    return memory::AllocateShared<udp::socket>(std::move(executor));
  }

  // A socket key identifies one listener generation. Duplicate attachment is
  // rejected; replacing a listener first closes and joins the old ingress.
  [[nodiscard]] SocketPtr AttachSocket(std::string socket_key,
                                       SocketPtr socket);
  [[nodiscard]] SocketPtr FindSocket(std::string_view socket_key) noexcept;
  [[nodiscard]] std::shared_ptr<const udp::socket>
  FindSocket(std::string_view socket_key) const noexcept;
  [[nodiscard]] bool OwnsSocket(std::string_view socket_key,
                                const udp::socket *socket) const noexcept;
  void CloseSocket(std::string_view socket_key) noexcept;
  void CloseAllSockets() noexcept;

private:
  class Association;
  friend class UdpAssociationReclaimer;
  void ReportBackgroundFailure(std::exception_ptr failure) noexcept;
  void ReclaimAssociation(UdpAssociationHook &hook,
                          std::chrono::steady_clock::time_point now) noexcept;

  struct Impl;
  std::shared_ptr<Impl> impl_;
};

} // namespace acpp::inbound_detail
