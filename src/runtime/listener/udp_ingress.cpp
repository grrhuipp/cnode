#include "udp_ingress.hpp"
#include "udp_association_reclaimer.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <exception>
#include <optional>
#include <stdexcept>
#include <utility>

namespace acpp::inbound_detail {
namespace {

constexpr size_t kAssociationMessageCapacity = 256;
constexpr size_t kListenerMessageCapacity = 512;
constexpr size_t kMaxQueuedDatagrams = 256;
constexpr size_t kMaxQueuedBytes = 512 * 1024;

[[nodiscard]] bool WouldOverflowQueue(size_t queued_datagrams,
                                      size_t queued_bytes,
                                      size_t payload_size) noexcept {
  return queued_datagrams >= kMaxQueuedDatagrams ||
         payload_size > kMaxQueuedBytes ||
         queued_bytes > kMaxQueuedBytes - payload_size;
}

template <class Map>
[[nodiscard]] auto FindOrEmplaceStringKey(Map &map, std::string_view key) {
  auto it = map.find(key);
  if (it != map.end())
    return std::pair{it, false};
  return map.try_emplace(memory::DataString{key});
}

} // namespace

class UdpIngress::Association final
    : public transport::MultiBufferReader,
      public transport::MultiBufferWriter,
      public memory::DataAllocated,
      public std::enable_shared_from_this<UdpIngress::Association> {
public:
  using ReplyCallback = RoutedPacketCallback;

  struct RequestData {
    RequestData(net::any_io_executor executor,
                routing::DispatchPolicy dispatch_policy)
        : context(std::move(executor)), policy(std::move(dispatch_policy)) {}

    session::Context context;
    routing::DispatchPolicy policy;
    routing::Dispatcher *dispatcher = nullptr;
    TimeoutsConfig timeouts;
    StatsShard stats;
  };

  Association(net::any_io_executor executor, std::weak_ptr<Impl> owner,
              std::string socket_key, std::string client_key, uint64_t id,
              InboundDatagramOwner authenticated_owner,
              ReplyCallback reply_callback)
      : executor_(std::move(executor)),
        input_channel_(executor_, kAssociationMessageCapacity),
        stop_channel_(executor_, 1), watcher_done_(executor_, 1),
        owner_(std::move(owner)),
        socket_key_(std::move(socket_key)), client_key_(std::move(client_key)),
        id_(id), authenticated_owner_(std::move(authenticated_owner)),
        reply_callback_(std::move(reply_callback)) {}

  [[nodiscard]] net::any_io_executor Executor() const { return executor_; }
  [[nodiscard]] uint64_t ID() const noexcept { return id_; }

  RequestData &PrepareRequest(routing::DispatchPolicy policy) {
    return request_.emplace(executor_, std::move(policy));
  }

  [[nodiscard]] bool SubmitInput(TargetAddress target,
                                 udp::endpoint reply_endpoint,
                                 buf::MultiBuffer payload) {
    const size_t payload_size = buf::TotalLen(payload);
    if (payload_size == 0)
      return false;
    if (payload_size > kMaxQueuedBytes) {
      RequestStop(ErrorCode::RESOURCE_EXHAUSTED);
      return false;
    }
    for (buf::Buffer *buffer : payload) {
      if (buffer && !buffer->IsEmpty())
        buffer->SetUDP(target);
    }
    if (input_channel_.try_send(
            std::exception_ptr{},
            InputMessage{std::move(reply_endpoint), std::move(payload)})) {
      return true;
    }
    RequestStop(ErrorCode::RESOURCE_EXHAUSTED);
    return false;
  }

  void RequestStop(ErrorCode reason = ErrorCode::OK) noexcept;

  void Start() {
    auto self = shared_from_this();
    std::weak_ptr<Association> weak_self = self;
    net::co_spawn(
        executor_, Run(std::move(self)),
        [weak_self = std::move(weak_self)](std::exception_ptr failure) noexcept {
          // Run owns the association until completion. Avoid extending its
          // lifetime in the co_spawn completion handler as well.
          if (failure) {
            if (auto self = weak_self.lock();
                self && !self->background_failure_) {
              self->background_failure_ = std::move(failure);
            }
          }
        });
  }

  transport::CancellationSource &Cancellation() noexcept override {
    return cancellation_;
  }

  net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
    if (closed_) {
      if (terminal_error_ == ErrorCode::RESOURCE_EXHAUSTED) {
        throw IoSystemError(io_error::no_buffer_space,
                            "UDP association input queue full");
      }
      co_return buf::MultiBuffer{};
    }
    try {
      auto input = co_await input_channel_.async_receive(net::use_awaitable);
      reply_endpoint_ = std::move(input.reply_endpoint);
      co_return std::move(input.payload);
    } catch (const std::system_error &) {
      if (terminal_error_ == ErrorCode::RESOURCE_EXHAUSTED) {
        throw IoSystemError(io_error::no_buffer_space,
                            "UDP association input queue full");
      }
      co_return buf::MultiBuffer{};
    }
  }

  net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
    if (closed_ || !reply_callback_) {
      payload.clear();
      throw IoSystemError(io_error::operation_aborted,
                          "UDP association reply path closed");
    }

    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
      payload.clear();
      co_return;
    }
    if (!datagram.Valid()) {
      payload.clear();
      throw IoSystemError(io_error::invalid_argument,
                          "UDP association reply has mixed endpoints");
    }

    std::span<const uint8_t> bytes;
    memory::ByteVector coalesced;
    if (datagram.buffer_count == 1) {
      bytes = datagram.single_buffer->Bytes();
    } else {
      coalesced.reserve(datagram.payload_size);
      for (const buf::Buffer *buffer : payload) {
        if (!buffer || buffer->IsEmpty())
          continue;
        const auto part = buffer->Bytes();
        coalesced.insert(coalesced.end(), part.begin(), part.end());
      }
      bytes = coalesced;
    }

    if (!reply_callback_(UDPPacketView{*datagram.target, bytes},
                         reply_endpoint_)) {
      payload.clear();
      throw IoSystemError(io_error::no_buffer_space,
                          "UDP listener reply queue full");
    }
    payload.clear();
  }

private:
  struct InputMessage {
    udp::endpoint reply_endpoint;
    buf::MultiBuffer payload;
  };

  static net::awaitable<void> WatchStop(std::shared_ptr<Association> self) {
    try {
      const ErrorCode reason =
          co_await self->stop_channel_.async_receive(net::use_awaitable);
      self->CloseOnOwner(reason);
    } catch (...) {
      if (!self->dispatch_finished_)
        self->CloseOnOwner(ErrorCode::CANCELLED);
    }
  }

  static net::awaitable<void> Run(std::shared_ptr<Association> self) {
    bool watcher_started = false;
    try {
      auto watcher_owner = self;
      net::co_spawn(
          self->executor_, WatchStop(watcher_owner),
          [self](std::exception_ptr failure) noexcept {
            try {
              if (!self->watcher_done_.try_send(std::move(failure))) {
                if (!self->background_failure_) {
                  self->background_failure_ = std::make_exception_ptr(
                      std::logic_error("UDP stop watcher completion lost"));
                }
                self->watcher_done_.close();
              }
            } catch (...) {
              if (!self->background_failure_)
                self->background_failure_ = std::current_exception();
              try {
                self->watcher_done_.close();
              } catch (...) {
              }
            }
          });
      watcher_started = true;
    } catch (...) {
      self->background_failure_ = std::current_exception();
      self->CloseOnOwner(ErrorCode::RESOURCE_EXHAUSTED);
    }

    std::exception_ptr session_failure;
    try {
      if (!self->request_ || !self->request_->dispatcher) {
        throw std::logic_error("UDP association request is not prepared");
      }
      auto &request = *self->request_;
      const RelayResult result = co_await request.dispatcher->Dispatch(
          self->executor_, request.policy, nullptr,
          transport::Link{self.get(), self.get()}, InitialPayload{},
          request.context, request.stats, request.timeouts);
      if (result.error != ErrorCode::OK) {
        LOG_CONN_DEBUG(request.context,
                       "[UDP] dispatcher session end: {} up={}B down={}B",
                       ErrorCodeToString(result.error), result.bytes_up,
                       result.bytes_down);
      }
    } catch (...) {
      session_failure = std::current_exception();
      if (self->request_)
        self->request_->stats.OnError();
    }

    self->CloseOnOwner(ErrorCode::OK);
    self->dispatch_finished_ = true;
    try {
      self->stop_channel_.close();
    } catch (...) {
      if (!self->background_failure_)
        self->background_failure_ = std::current_exception();
    }
    if (watcher_started) {
      try {
        co_await self->watcher_done_.async_receive(net::use_awaitable);
      } catch (...) {
        if (!self->background_failure_)
          self->background_failure_ = std::current_exception();
      }
    }
    StatsSnapshot snapshot{};
    if (self->request_)
      snapshot = self->request_->stats.Snapshot();
    co_await self->DeliverCompletion(snapshot);

    if (session_failure) {
      try {
        std::rethrow_exception(session_failure);
      } catch (const std::exception &error) {
        if (self->request_) {
          LOG_CONN_DEBUG(self->request_->context,
                         "UDP dispatcher coroutine failed: {}", error.what());
        } else {
          LOG_NET_DEBUG("UDP dispatcher coroutine failed: {}", error.what());
        }
      } catch (...) {
        LOG_NET_DEBUG("UDP dispatcher coroutine failed: unknown");
      }
    }
  }

  void CloseOnOwner(ErrorCode reason) noexcept {
    if (closed_)
      return;
    closed_ = true;
    terminal_error_ = reason;
    cancellation_.Stop(reason);
    try {
      input_channel_.close();
    } catch (...) {
      if (!background_failure_)
        background_failure_ = std::current_exception();
      try {
        input_channel_.cancel();
      } catch (...) {
      }
    }
  }

  net::awaitable<void> DeliverCompletion(StatsSnapshot snapshot);

  net::any_io_executor executor_;
  net::experimental::concurrent_channel<
      void(std::exception_ptr, InputMessage)>
      input_channel_;
  net::experimental::concurrent_channel<void(std::exception_ptr, ErrorCode)>
      stop_channel_;
  net::experimental::concurrent_channel<void(std::exception_ptr)>
      watcher_done_;
  std::weak_ptr<Impl> owner_;
  std::string socket_key_;
  std::string client_key_;
  uint64_t id_ = 0;
  InboundDatagramOwner authenticated_owner_;
  ReplyCallback reply_callback_;
  udp::endpoint reply_endpoint_;
  bool closed_ = false;
  bool dispatch_finished_ = false;
  // Accessed only by the listener owner strand.
  bool stop_submitted_ = false;
  ErrorCode terminal_error_ = ErrorCode::OK;
  transport::CancellationSource cancellation_;
  std::optional<RequestData> request_;
  std::exception_ptr background_failure_;
};

struct UdpIngress::Impl final
    : public memory::DataAllocated,
      public std::enable_shared_from_this<UdpIngress::Impl> {
  struct SocketEntry {
    SocketPtr socket;
    uint64_t generation = 0;
  };

  class PendingReply final : public memory::DataAllocated {
  public:
    udp::endpoint endpoint;
    buf::MultiBuffer payload;
    size_t payload_size = 0;
    std::array<net::const_buffer, buf::MultiBuffer::kInlineCapacity>
        inline_buffers{};
    memory::DataVector<net::const_buffer> spill_buffers;
    size_t buffer_count = 0;

    void PrepareBuffers() {
      spill_buffers.clear();
      buffer_count = 0;
      for (const buf::Buffer *buffer : payload) {
        if (!buffer || buffer->IsEmpty())
          continue;
        const auto bytes = buffer->Bytes();
        const net::const_buffer send_buffer{bytes.data(), bytes.size()};
        if (buffer_count < inline_buffers.size()) {
          inline_buffers[buffer_count++] = send_buffer;
          continue;
        }
        if (spill_buffers.empty()) {
          spill_buffers.reserve(payload.size());
          spill_buffers.insert(spill_buffers.end(), inline_buffers.begin(),
                               inline_buffers.begin() + buffer_count);
        }
        spill_buffers.push_back(send_buffer);
        ++buffer_count;
      }
    }

    [[nodiscard]] std::span<const net::const_buffer> Buffers() const noexcept {
      if (!spill_buffers.empty())
        return spill_buffers;
      return {inline_buffers.data(), buffer_count};
    }
  };

  struct ReplyQueue {
    memory::DataDeque<std::unique_ptr<PendingReply>> pending;
    std::unique_ptr<PendingReply> active;
    size_t queued_bytes = 0;
    uint64_t socket_generation = 0;
    bool closing = false;
  };

  struct AssociationRow {
    std::weak_ptr<Association> association;
    InboundDatagramOwner authenticated_owner;
    std::chrono::steady_clock::time_point last_active;
    uint64_t id = 0;
    UdpAssociationHook reclaim_hook;
  };

  struct ReplyMessage {
    std::string socket_key;
    uint64_t socket_generation = 0;
    udp::endpoint endpoint;
    buf::MultiBuffer payload;
  };

  struct CompletionMessage {
    std::string socket_key;
    std::string client_key;
    uint64_t id = 0;
    StatsSnapshot snapshot;
    std::exception_ptr delivery_failure;
  };

  using ReplyChannel = net::experimental::concurrent_channel<
      void(std::exception_ptr, ReplyMessage)>;
  using CompletionChannel = net::experimental::concurrent_channel<
      void(std::exception_ptr, CompletionMessage)>;

  using SocketMap =
      memory::DataUnorderedMap<memory::DataString, SocketEntry,
                               TransparentStringHash, TransparentStringEq>;
  using ReplyMap =
      memory::DataUnorderedMap<memory::DataString, ReplyQueue,
                               TransparentStringHash, TransparentStringEq>;
  using AssociationMap =
      memory::DataUnorderedMap<memory::DataString, AssociationRow,
                               TransparentStringHash, TransparentStringEq>;
  using AssociationOuterMap =
      memory::DataUnorderedMap<memory::DataString, AssociationMap,
                               TransparentStringHash, TransparentStringEq>;

  enum class State : uint8_t { Running, Stopping, Drained };

  Impl(std::string tag_value, std::unique_ptr<::acpp::Inbound> proxy_value,
       UdpAssociationReclaimer &reclaimer_value,
       UdpAssociationQuota &quota_value, net::any_io_executor listener_executor,
       net::any_io_executor runtime_executor_value,
       StatsShard &aggregate_stats_value)
      : tag(std::string_view(tag_value)),
        proxy(std::move(proxy_value)), reclaimer(reclaimer_value),
        quota(quota_value), executor(std::move(listener_executor)),
        runtime_executor(std::move(runtime_executor_value)),
        reply_channel(executor, kListenerMessageCapacity),
        completion_channel(executor, UdpAssociationQuota::kCapacity),
        aggregate_stats(aggregate_stats_value), completion_signal(executor, 1) {
  }

  ~Impl() = default;

  void RememberFailure(std::exception_ptr failure) noexcept {
    if (!first_failure && failure)
      first_failure = std::move(failure);
  }

  void RememberCurrentFailure() noexcept {
    RememberFailure(std::current_exception());
  }

  void RememberLogicFailure(const char *message) noexcept {
    try {
      throw std::logic_error(message);
    } catch (...) {
      RememberCurrentFailure();
    }
  }

  void BeginStop() noexcept {
    if (state == State::Running)
      state = State::Stopping;
    CloseAllSocketsOnOwner();
    StopAllAssociations();
    CloseMessageChannelsIfReady();
    SignalDrained();
  }

  void RecordFailure(std::exception_ptr failure) noexcept {
    RememberFailure(std::move(failure));
    BeginStop();
  }

  void StopAssociation(
      const std::shared_ptr<Association> &association) noexcept {
    association->RequestStop();
  }

  void StopAllAssociations() noexcept {
    for (auto outer = associations.begin(); outer != associations.end();) {
      auto &rows = outer->second;
      for (auto row = rows.begin(); row != rows.end();) {
        reclaimer.Unregister(row->second.reclaim_hook);
        auto association = row->second.association.lock();
        if (association)
          StopAssociation(association);
        row = rows.erase(row);
      }
      outer = associations.erase(outer);
    }
  }

  void CloseSocketOnOwner(std::string_view socket_key) noexcept {
    auto socket_it = sockets.find(socket_key);
    if (socket_it == sockets.end())
      return;

    auto association_it = associations.find(socket_key);
    if (association_it != associations.end()) {
      auto &rows = association_it->second;
      for (auto row = rows.begin(); row != rows.end();) {
        reclaimer.Unregister(row->second.reclaim_hook);
        auto association = row->second.association.lock();
        if (association)
          StopAssociation(association);
        row = rows.erase(row);
      }
      associations.erase(association_it);
    }

    auto reply_it = replies.find(socket_key);
    if (reply_it != replies.end()) {
      reply_it->second.pending.clear();
      reply_it->second.queued_bytes = 0;
      reply_it->second.closing = true;
      if (!reply_it->second.active)
        replies.erase(reply_it);
    }

    auto socket = std::move(socket_it->second.socket);
    sockets.erase(socket_it);
    IoErrorCode ignored;
    socket->cancel(ignored);
    socket->close(ignored);
  }

  void CloseAllSocketsOnOwner() noexcept {
    while (!sockets.empty())
      CloseSocketOnOwner(sockets.begin()->first);
  }

  [[nodiscard]] SocketEntry *FindSocketEntry(std::string_view key) noexcept {
    auto it = sockets.find(key);
    return it == sockets.end() ? nullptr : &it->second;
  }

  [[nodiscard]] const SocketEntry *
  FindSocketEntry(std::string_view key) const noexcept {
    auto it = sockets.find(key);
    return it == sockets.end() ? nullptr : &it->second;
  }

  [[nodiscard]] bool SubmitReply(std::string socket_key,
                                 uint64_t socket_generation,
                                 udp::endpoint endpoint,
                                 buf::MultiBuffer payload) {
    return reply_channel.try_send(
        std::exception_ptr{},
        ReplyMessage{std::move(socket_key), socket_generation,
                     std::move(endpoint), std::move(payload)});
  }

  static net::awaitable<void> PumpReplies(std::shared_ptr<Impl> self) {
    while (true) {
      try {
        auto message =
            co_await self->reply_channel.async_receive(net::use_awaitable);
        self->EnqueueReplyOnOwner(
            std::move(message.socket_key), message.socket_generation,
            std::move(message.endpoint), std::move(message.payload));
      } catch (const std::system_error &error) {
        if (error.code() == net::experimental::error::channel_closed)
          co_return;
        throw;
      }
    }
  }

  static net::awaitable<void> PumpCompletions(std::shared_ptr<Impl> self) {
    while (true) {
      try {
        auto message =
            co_await self->completion_channel.async_receive(net::use_awaitable);
        self->RetireAssociation(std::move(message));
      } catch (const std::system_error &error) {
        if (error.code() == net::experimental::error::channel_closed)
          co_return;
        throw;
      }
    }
  }

  void FinishMessagePump(std::exception_ptr failure) noexcept {
    if (failure)
      RecordFailure(std::move(failure));
    if (active_message_pumps == 0) {
      RememberLogicFailure("UDP listener message-pump underflow");
      return;
    }
    --active_message_pumps;
    SignalDrained();
  }

  void StartMessagePumps() {
    auto self = shared_from_this();
    ++active_message_pumps;
    try {
      net::co_spawn(executor, PumpReplies(self),
                    [self](std::exception_ptr failure) noexcept {
                      self->FinishMessagePump(std::move(failure));
                    });
    } catch (...) {
      --active_message_pumps;
      throw;
    }

    ++active_message_pumps;
    try {
      net::co_spawn(executor, PumpCompletions(self),
                    [self](std::exception_ptr failure) noexcept {
                      self->FinishMessagePump(std::move(failure));
                    });
    } catch (...) {
      --active_message_pumps;
      channels_closed = true;
      try {
        reply_channel.close();
      } catch (...) {
      }
      try {
        completion_channel.close();
      } catch (...) {
      }
      throw;
    }
  }

  void EnqueueReplyOnOwner(std::string socket_key, uint64_t socket_generation,
                           udp::endpoint endpoint, buf::MultiBuffer payload) {
    if (state != State::Running)
      return;
    const auto *socket = FindSocketEntry(socket_key);
    if (!socket || socket->generation != socket_generation)
      return;
    const size_t payload_size = buf::TotalLen(payload);
    if (payload_size == 0)
      return;

    auto [queue_it, inserted] = FindOrEmplaceStringKey(replies, socket_key);
    auto &queue = queue_it->second;
    if (inserted)
      queue.socket_generation = socket_generation;
    if (queue.socket_generation != socket_generation || queue.closing ||
        WouldOverflowQueue(queue.pending.size(), queue.queued_bytes,
                           payload_size)) {
      ++message_drops;
      return;
    }

    auto reply = std::make_unique<PendingReply>();
    reply->endpoint = std::move(endpoint);
    reply->payload = std::move(payload);
    reply->payload_size = payload_size;
    queue.queued_bytes += payload_size;
    queue.pending.push_back(std::move(reply));
    ++reply_datagrams;
    reply_bytes += payload_size;
    if (!queue.active)
      StartReplySend(socket_key, queue);
  }

  void StartReplySend(std::string_view socket_key, ReplyQueue &queue) noexcept {
    bool sender_registered = false;
    try {
      if (queue.active || queue.pending.empty() || queue.closing)
        return;
      auto *socket_entry = FindSocketEntry(socket_key);
      if (!socket_entry ||
          socket_entry->generation != queue.socket_generation) {
        queue.pending.clear();
        queue.queued_bytes = 0;
        return;
      }

      queue.active = std::move(queue.pending.front());
      queue.pending.pop_front();
      queue.queued_bytes -=
          std::min(queue.queued_bytes, queue.active->payload_size);
      queue.active->PrepareBuffers();
      ++active_reply_senders;
      sender_registered = true;

      auto self = shared_from_this();
      const std::string owned_key(socket_key);
      const uint64_t generation = queue.socket_generation;
      socket_entry->socket->async_send_to(
          queue.active->Buffers(), queue.active->endpoint,
          [self = std::move(self), owned_key, generation](IoErrorCode error,
                                                          size_t) mutable {
            self->FinishReplySend(owned_key, generation, error);
          });
    } catch (...) {
      if (queue.active) {
        queue.active.reset();
      }
      if (sender_registered && active_reply_senders != 0) {
        --active_reply_senders;
      }
      RecordFailure(std::current_exception());
    }
  }

  void FinishReplySend(std::string_view socket_key, uint64_t socket_generation,
                       const IoErrorCode &) noexcept {
    auto it = replies.find(socket_key);
    if (it == replies.end() ||
        it->second.socket_generation != socket_generation ||
        !it->second.active) {
      if (active_reply_senders != 0)
        --active_reply_senders;
      RememberLogicFailure("UDP reply completion has no active send");
      BeginStop();
      return;
    }
    auto &queue = it->second;
    queue.active.reset();
    if (active_reply_senders == 0) {
      RememberLogicFailure("UDP active reply sender underflow");
      BeginStop();
      return;
    }
    --active_reply_senders;

    if (queue.closing || state != State::Running) {
      replies.erase(it);
    } else if (!queue.pending.empty()) {
      StartReplySend(socket_key, queue);
    } else {
      replies.erase(it);
    }
    SignalDrained();
  }

  void RetireAssociation(CompletionMessage message) noexcept {
    if (message.delivery_failure)
      RecordFailure(std::move(message.delivery_failure));
    auto outer = associations.find(message.socket_key);
    if (outer != associations.end()) {
      auto row = outer->second.find(message.client_key);
      if (row != outer->second.end() && row->second.id == message.id) {
        reclaimer.Unregister(row->second.reclaim_hook);
        outer->second.erase(row);
        if (outer->second.empty())
          associations.erase(outer);
      }
    }

    if (active_associations == 0) {
      RememberLogicFailure("UDP active association underflow");
      BeginStop();
      return;
    }
    --active_associations;
    quota.Release();
    aggregate_stats.hot.bytes_in += message.snapshot.bytes_in;
    aggregate_stats.hot.bytes_out += message.snapshot.bytes_out;
    aggregate_stats.cold.errors += message.snapshot.errors;
    aggregate_stats.OnConnectionClosed();
    CloseMessageChannelsIfReady();
    SignalDrained();
  }

  void CloseMessageChannelsIfReady() noexcept {
    if (state == State::Running || active_associations != 0 || channels_closed)
      return;
    channels_closed = true;
    try {
      reply_channel.close();
    } catch (...) {
      RememberCurrentFailure();
      try {
        reply_channel.cancel();
      } catch (...) {
      }
    }
    try {
      completion_channel.close();
    } catch (...) {
      RememberCurrentFailure();
      try {
        completion_channel.cancel();
      } catch (...) {
      }
    }
  }

  void SignalDrained() noexcept {
    CloseMessageChannelsIfReady();
    if (state != State::Stopping || active_associations != 0 ||
        active_reply_senders != 0 || active_message_pumps != 0) {
      return;
    }
    state = State::Drained;
    if (join_observers != 0) {
      try {
        (void)completion_signal.try_send(std::exception_ptr{});
      } catch (...) {
        RememberCurrentFailure();
        completion_signal.close();
      }
    }
  }

  memory::DataString tag;
  std::unique_ptr<::acpp::Inbound> proxy;
  UdpAssociationReclaimer &reclaimer;
  UdpAssociationQuota &quota;
  net::any_io_executor executor;
  net::any_io_executor runtime_executor;
  ReplyChannel reply_channel;
  CompletionChannel completion_channel;
  StatsShard &aggregate_stats;
  SocketMap sockets;
  ReplyMap replies;
  AssociationOuterMap associations;
  net::experimental::concurrent_channel<void(std::exception_ptr)>
      completion_signal;
  size_t active_associations = 0;
  size_t active_reply_senders = 0;
  size_t active_message_pumps = 0;
  size_t join_observers = 0;
  uint64_t next_socket_generation = 0;
  uint64_t input_datagrams = 0;
  uint64_t input_bytes = 0;
  uint64_t reply_datagrams = 0;
  uint64_t reply_bytes = 0;
  uint64_t association_drops = 0;
  uint64_t message_drops = 0;
  std::exception_ptr first_failure;
  bool channels_closed = false;
  State state = State::Running;
};

void UdpIngress::Association::RequestStop(ErrorCode reason) noexcept {
  if (stop_submitted_)
    return;
  stop_submitted_ = true;
  try {
    if (stop_channel_.try_send(std::exception_ptr{}, reason))
      return;
  } catch (...) {
    if (auto owner = owner_.lock())
      owner->RecordFailure(std::current_exception());
  }
  // Closing wakes the watcher even when construction of the terminal message
  // failed. The association strand maps this fallback to CANCELLED.
  try {
    stop_channel_.close();
  } catch (...) {
    if (auto owner = owner_.lock())
      owner->RecordFailure(std::current_exception());
  }
}

net::awaitable<void>
UdpIngress::Association::DeliverCompletion(StatsSnapshot snapshot) {
  auto owner = owner_.lock();
  if (!owner)
    co_return;
  co_await owner->completion_channel.async_send(
      std::exception_ptr{},
      Impl::CompletionMessage{socket_key_, client_key_, id_, snapshot,
                              background_failure_},
      net::use_awaitable);
}

UdpIngress::UdpIngress(std::string tag, std::unique_ptr<::acpp::Inbound> proxy,
                       UdpAssociationReclaimer &reclaimer,
                       UdpAssociationQuota &quota,
                       net::any_io_executor listener_executor,
                       net::any_io_executor runtime_executor,
                       StatsShard &aggregate_stats)
    : impl_(memory::AllocateShared<Impl>(
          std::move(tag), std::move(proxy), reclaimer, quota,
          std::move(listener_executor), std::move(runtime_executor),
          aggregate_stats)) {}

UdpIngress::~UdpIngress() noexcept = default;

std::string_view UdpIngress::Tag() const noexcept { return impl_->tag; }

net::any_io_executor UdpIngress::Executor() const { return impl_->executor; }

UdpIngress::ResourceStats UdpIngress::GetResourceStats() const noexcept {
  size_t visible_associations = 0;
  for (const auto &[socket_key, rows] : impl_->associations) {
    (void)socket_key;
    visible_associations += rows.size();
  }
  return ResourceStats{
      .associations = visible_associations,
      .retiring_associations =
          impl_->active_associations - visible_associations,
      .input_datagrams = impl_->input_datagrams,
      .input_bytes = impl_->input_bytes,
      .reply_datagrams = impl_->reply_datagrams,
      .reply_bytes = impl_->reply_bytes,
      .active_reply_senders = impl_->active_reply_senders,
      .native_dispatches = impl_->active_associations,
      .association_drops = impl_->association_drops,
      .message_drops = impl_->message_drops,
  };
}

bool UdpIngress::ReplaceHandler(
    std::unique_ptr<::acpp::Inbound> proxy) noexcept {
  if (!proxy || impl_->state != Impl::State::Running)
    return false;
  if (impl_->proxy)
    proxy->AdoptOwnerStateFrom(*impl_->proxy);
  impl_->proxy = std::move(proxy);
  return true;
}

void UdpIngress::RequestStop() noexcept { impl_->BeginStop(); }

void UdpIngress::ReportBackgroundFailure(std::exception_ptr failure) noexcept {
  impl_->RecordFailure(std::move(failure));
}

net::awaitable<void> UdpIngress::AsyncJoin() {
  const bool previous = co_await net::this_coro::throw_if_cancelled();
  co_await net::this_coro::throw_if_cancelled(false);
  if (impl_->join_observers != 0) {
    co_await net::this_coro::throw_if_cancelled(previous);
    throw std::logic_error("UdpIngress AsyncJoin supports one observer");
  }
  ++impl_->join_observers;
  struct ObserverGuard {
    size_t &count;
    ~ObserverGuard() { --count; }
  } guard{impl_->join_observers};
  impl_->BeginStop();
  while (impl_->active_associations != 0 ||
         impl_->active_reply_senders != 0 ||
         impl_->active_message_pumps != 0) {
    try {
      co_await impl_->completion_signal.async_receive(
          net::bind_cancellation_slot(net::cancellation_slot{},
                                      net::use_awaitable));
    } catch (...) {
      impl_->RememberCurrentFailure();
      if (impl_->active_associations != 0 ||
          impl_->active_reply_senders != 0 ||
          impl_->active_message_pumps != 0) {
        break;
      }
    }
  }
  if (impl_->state == Impl::State::Stopping)
    impl_->state = Impl::State::Drained;

  std::exception_ptr failure = impl_->first_failure;
  if (!failure)
    failure = impl_->reclaimer.Failure();
  co_await net::this_coro::throw_if_cancelled(previous);
  if (failure)
    std::rethrow_exception(failure);
}

bool UdpIngress::ProcessDatagram(const UdpDatagramContext &datagram) {
  if (impl_->state != Impl::State::Running || !impl_->proxy ||
      !datagram.socket || datagram.payload.empty() || !datagram.receiver) {
    return false;
  }

  const auto *socket_entry = impl_->FindSocketEntry(datagram.socket_key);
  if (!socket_entry || socket_entry->socket.get() != datagram.socket)
    return false;
  const uint64_t socket_generation = socket_entry->generation;
  const auto now = std::chrono::steady_clock::now();
  const std::string client_ip =
      iputil::NormalizeAddressString(datagram.client_endpoint.address());
  const auto normalized_client_addr =
      iputil::NormalizeAddress(datagram.client_endpoint.address());

  auto decoded = impl_->proxy->Process(InboundDatagramRequest{
      .tag = impl_->tag,
      .client_ip = client_ip,
      .payload = datagram.payload,
  });
  if (!decoded)
    return false;

  std::string protocol_key =
      decoded->session_key.empty()
          ? iputil::FormatEndpointForLog(client_ip,
                                         datagram.client_endpoint.port())
          : decoded->session_key;
  std::string client_key = decoded->session_owner.ScopeSessionKey(protocol_key);
  if (client_key.empty())
    return false;

  // Cold candidates and idle listeners own no suspended message-pump frames.
  if (impl_->active_message_pumps == 0) impl_->StartMessagePumps();
  if (impl_->state != Impl::State::Running) return false;

  const std::string socket_key(datagram.socket_key);
  auto outer = impl_->associations.find(socket_key);
  Association *existing_identity = nullptr;
  std::shared_ptr<Association> association;
  if (outer != impl_->associations.end()) {
    auto row = outer->second.find(client_key);
    if (row != outer->second.end()) {
      const bool expired =
          row->second.reclaim_hook.idle_timeout.count() > 0 &&
          now - row->second.last_active > row->second.reclaim_hook.idle_timeout;
      association = row->second.association.lock();
      const bool owner_mismatch =
          association &&
          !row->second.authenticated_owner.Same(decoded->session_owner);
      if (owner_mismatch) {
        impl_->reclaimer.Unregister(row->second.reclaim_hook);
        impl_->StopAssociation(association);
        outer->second.erase(row);
        if (outer->second.empty())
          impl_->associations.erase(outer);
        association.reset();
      } else if (!association || expired) {
        ReclaimAssociation(row->second.reclaim_hook, now);
        association.reset();
      } else {
        existing_identity = association.get();
      }
    }
  }

  if (!association) {
    if (!decoded->response || datagram.candidate_conn_id == 0 ||
        !impl_->quota.TryAcquire()) {
      ++impl_->association_drops;
      return false;
    }
    auto quota_guard = std::unique_ptr<void, void (*)(void *)>(
        &impl_->quota, [](void *pointer) {
          static_cast<UdpAssociationQuota *>(pointer)->Release();
        });
    const auto association_executor = net::make_strand(impl_->runtime_executor);
    auto response = std::move(decoded->response);
    std::weak_ptr<Impl> weak_owner = impl_;
    Association::ReplyCallback reply_callback{
        [weak_owner, socket_key, socket_generation,
         response = std::move(response)](
            UDPPacketView packet,
            const udp::endpoint &reply_endpoint) mutable -> bool {
          auto owner = weak_owner.lock();
          if (!owner)
            return false;
          auto payload = response->Encode(packet);
          if (payload.empty())
            return false;
          return owner->SubmitReply(socket_key, socket_generation,
                                    reply_endpoint, std::move(payload));
        }};

    association = memory::AllocateShared<Association>(
        association_executor, std::weak_ptr<Impl>(impl_), socket_key, client_key,
        datagram.candidate_conn_id, decoded->session_owner,
        std::move(reply_callback));

    auto &request =
        association->PrepareRequest(datagram.receiver->dispatch_policy);
    request.dispatcher = &datagram.dispatcher;
    request.timeouts = datagram.timeouts;
    auto &context = request.context;
    context.conn_id = datagram.candidate_conn_id;
    context.runtime_generation = datagram.runtime_generation;
    context.config_generation = datagram.config_generation;
    const std::string_view inbound_tag =
        datagram.receiver->inbound_tag.empty()
            ? std::string_view(impl_->tag)
            : std::string_view(datagram.receiver->inbound_tag);
    context.inbound.tag.assign(inbound_tag);
    if (const auto *tags = datagram.receiver->RouteInboundTags()) {
      context.inbound.tags.reserve(tags->size());
      for (const auto &tag : *tags)
        context.inbound.tags.emplace_back(tag);
    }
    context.inbound.source_ip.assign(client_ip);
    context.inbound.source_addr = normalized_client_addr;
    context.inbound.source_port = datagram.client_endpoint.port();
    context.inbound.peer_ip.assign(client_ip);
    context.inbound.peer_port = datagram.client_endpoint.port();
    IoErrorCode endpoint_error;
    const auto local_endpoint = datagram.socket->local_endpoint(endpoint_error);
    if (!endpoint_error && !local_endpoint.address().is_unspecified()) {
      context.inbound.local_endpoint =
          tcp::endpoint(iputil::NormalizeAddress(local_endpoint.address()),
                        local_endpoint.port());
    }
    context.content.network = Network::UDP;
    context.outbound.original_target = decoded->target;
    context.outbound.target = decoded->target;
    context.inbound.user_id = decoded->user_id;
    context.inbound.user_email.assign(decoded->user_email);
    context.inbound.protocol.assign(datagram.receiver->protocol);
    context.inbound.transport = "udp";
    context.inbound.security.assign(
        datagram.receiver->stream_settings.security);
    context.content.speed_limit = decoded->speed_limit;
    auto [outer_it, outer_inserted] =
        FindOrEmplaceStringKey(impl_->associations, socket_key);
    (void)outer_inserted;
    auto [row_it, inserted] = outer_it->second.try_emplace(
        memory::DataString{std::string_view(client_key)},
        Impl::AssociationRow{
            .association = association,
            .authenticated_owner = decoded->session_owner,
            .last_active = now,
            .id = datagram.candidate_conn_id,
            .reclaim_hook = {},
        });
    if (!inserted) {
      ++impl_->association_drops;
      return false;
    }
    try {
      impl_->reclaimer.Register(row_it->second.reclaim_hook, *this,
                                outer_it->first, row_it->first,
                                datagram.timeouts.SessionIdleTimeout());
    } catch (...) {
      outer_it->second.erase(row_it);
      if (outer_it->second.empty())
        impl_->associations.erase(outer_it);
      throw;
    }
    ++impl_->active_associations;
    impl_->aggregate_stats.OnConnectionAccepted();
    quota_guard.release();

    try {
      association->Start();
    } catch (...) {
      impl_->reclaimer.Unregister(row_it->second.reclaim_hook);
      outer_it->second.erase(row_it);
      if (outer_it->second.empty())
        impl_->associations.erase(outer_it);
      --impl_->active_associations;
      impl_->quota.Release();
      impl_->aggregate_stats.OnConnectionClosed();
      throw;
    }
  }

  if (!association ||
      (existing_identity && association.get() != existing_identity)) {
    return false;
  }
  if (!association->SubmitInput(std::move(decoded->target),
                                datagram.client_endpoint,
                                std::move(decoded->payload))) {
    ++impl_->message_drops;
    return association->ID() == datagram.candidate_conn_id;
  }
  ++impl_->input_datagrams;
  impl_->input_bytes += datagram.payload.size();

  outer = impl_->associations.find(socket_key);
  if (outer != impl_->associations.end()) {
    auto row = outer->second.find(client_key);
    if (row != outer->second.end() && row->second.id == association->ID()) {
      row->second.last_active = now;
    }
  }
  return association->ID() == datagram.candidate_conn_id;
}

UdpIngress::SocketPtr UdpIngress::AttachSocket(std::string socket_key,
                                               SocketPtr socket) {
  if (!socket || impl_->state != Impl::State::Running ||
      impl_->sockets.contains(socket_key)) {
    return nullptr;
  }
  if (++impl_->next_socket_generation == 0) {
    ++impl_->next_socket_generation;
  }
  auto [it, inserted] = impl_->sockets.try_emplace(
      memory::DataString{std::string_view(socket_key)},
      Impl::SocketEntry{socket, impl_->next_socket_generation});
  (void)it;
  return inserted ? std::move(socket) : nullptr;
}

UdpIngress::SocketPtr
UdpIngress::FindSocket(std::string_view socket_key) noexcept {
  const auto *entry = impl_->FindSocketEntry(socket_key);
  return entry ? entry->socket : nullptr;
}

std::shared_ptr<const udp::socket>
UdpIngress::FindSocket(std::string_view socket_key) const noexcept {
  const auto *entry = impl_->FindSocketEntry(socket_key);
  return entry ? entry->socket : nullptr;
}

bool UdpIngress::OwnsSocket(std::string_view socket_key,
                            const udp::socket *socket) const noexcept {
  const auto *entry = impl_->FindSocketEntry(socket_key);
  return socket && entry && entry->socket.get() == socket;
}

void UdpIngress::ReclaimAssociation(
    UdpAssociationHook &hook,
    std::chrono::steady_clock::time_point now) noexcept {
  auto outer = impl_->associations.find(hook.socket_key);
  if (outer == impl_->associations.end()) {
    impl_->reclaimer.Unregister(hook);
    return;
  }
  auto row = outer->second.find(hook.client_key);
  if (row == outer->second.end() || &row->second.reclaim_hook != &hook) {
    impl_->reclaimer.Unregister(hook);
    return;
  }
  const bool expired = !row->second.association.lock() ||
                       (hook.idle_timeout.count() > 0 &&
                        now - row->second.last_active > hook.idle_timeout);
  if (!expired)
    return;

  auto association = row->second.association.lock();
  impl_->reclaimer.Unregister(row->second.reclaim_hook);
  if (association)
    impl_->StopAssociation(association);
  outer->second.erase(row);
  if (outer->second.empty())
    impl_->associations.erase(outer);
}

void UdpIngress::CloseSocket(std::string_view socket_key) noexcept {
  impl_->CloseSocketOnOwner(socket_key);
}

void UdpIngress::CloseAllSockets() noexcept {
  impl_->CloseAllSocketsOnOwner();
}

} // namespace acpp::inbound_detail
