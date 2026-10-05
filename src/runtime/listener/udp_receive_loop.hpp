#pragma once

#include "udp_receive_buffer.hpp"

#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>

namespace acpp::inbound_detail {

namespace {
[[nodiscard]] inline bool
IsTransientReceiveError(const IoErrorCode &error) noexcept {
  return error == io_error::would_block || error == io_error::try_again ||
         error == io_error::interrupted ||
         error == io_error::connection_refused ||
         error == io_error::connection_reset;
}
} // namespace

template <class IsOwned, class ProcessDatagram>
net::awaitable<void>
RunUdpReceiveLoop(std::shared_ptr<udp::socket> socket, IsOwned is_owned,
                  ProcessDatagram process_datagram, uint64_t &resource_drops) {
  static_assert(
      std::is_nothrow_invocable_r_v<bool, IsOwned &,
                                    const std::shared_ptr<udp::socket> &>);
  static_assert(std::is_same_v<
                std::invoke_result_t<ProcessDatagram &, const udp::endpoint &,
                                     std::span<const uint8_t>>,
                void>);
  detail::UdpReceiveBuffer receive_buffer;
  while (true) {
    receive_buffer.Release();
    if (!is_owned(socket)) {
      co_return;
    }

    auto [wait_error] = co_await socket->async_wait(
        udp::socket::wait_read, net::as_tuple(net::use_awaitable));
    if (!is_owned(socket)) {
      co_return;
    }
    if (wait_error) {
      if (IsTransientReceiveError(wait_error)) {
        continue;
      }
      throw IoSystemError(wait_error);
    }

    IoErrorCode available_error;
    const size_t available = socket->available(available_error);
    if (!is_owned(socket)) {
      co_return;
    }
    if (available_error) {
      if (IsTransientReceiveError(available_error)) {
        continue;
      }
      throw IoSystemError(available_error);
    }

    const auto storage = receive_buffer.Prepare(available);
    if (storage.size() == 0) {
      udp::endpoint discarded_peer;
      std::array<uint8_t, 1> discard_byte{};
      IoErrorCode discard_error;
      (void)socket->receive_from(net::buffer(discard_byte), discarded_peer, 0,
                                 discard_error);
      if (!is_owned(socket)) {
        co_return;
      }
      if (IsTransientReceiveError(discard_error)) {
        continue;
      }
      if (discard_error && discard_error != io_error::message_size) {
        throw IoSystemError(discard_error);
      }
      ++resource_drops;
      continue;
    }

    udp::endpoint peer;
    auto [receive_error, received_bytes] = co_await socket->async_receive_from(
        storage, peer, net::as_tuple(net::use_awaitable));
    if (!is_owned(socket)) {
      co_return;
    }
    if (receive_error == io_error::message_size) {
      ++resource_drops;
      continue;
    }
    if (receive_error) {
      if (IsTransientReceiveError(receive_error)) {
        continue;
      }
      throw IoSystemError(receive_error);
    }
    if (received_bytes == 0) {
      continue;
    }

    const auto payload = receive_buffer.Data(received_bytes);
    try {
      process_datagram(peer, payload);
    } catch (const std::bad_alloc &) {
      ++resource_drops;
    }
  }
}

} // namespace acpp::inbound_detail
