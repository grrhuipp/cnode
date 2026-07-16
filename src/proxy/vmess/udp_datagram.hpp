#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/target_address.hpp"

#include <limits>
#include <span>

namespace acpp::vmess {

class ContiguousUdpDatagram {
public:
    explicit ContiguousUdpDatagram(const buf::MultiBuffer& payload) {
        const buf::Buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t payload_size = 0;
        for (const buf::Buffer* buffer : payload) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            if (buffer->Len() >
                std::numeric_limits<size_t>::max() - payload_size) {
                throw IoSystemError(
                    io_error::message_size, "VMess UDP datagram is too large");
            }
            single = buffer;
            ++buffer_count;
            payload_size += buffer->Len();
        }
        if (buffer_count == 1) {
            bytes_ = single->Bytes();
            return;
        }
        owned_.reserve(payload_size);
        for (const buf::Buffer* buffer : payload) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            owned_.insert(owned_.end(), bytes.begin(), bytes.end());
        }
        bytes_ = owned_;
    }

    explicit ContiguousUdpDatagram(
        std::span<const net::const_buffer> payload) {
        const net::const_buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t payload_size = 0;
        for (const auto& buffer : payload) {
            if (buffer.size() == 0) {
                continue;
            }
            if (!buffer.data()) {
                throw IoSystemError(
                    io_error::invalid_argument,
                    "VMess UDP datagram contains a null payload buffer");
            }
            if (buffer.size() >
                std::numeric_limits<size_t>::max() - payload_size) {
                throw IoSystemError(
                    io_error::message_size, "VMess UDP datagram is too large");
            }
            single = &buffer;
            ++buffer_count;
            payload_size += buffer.size();
        }
        if (buffer_count == 1) {
            bytes_ = std::span<const uint8_t>(
                static_cast<const uint8_t*>(single->data()), single->size());
            return;
        }
        owned_.reserve(payload_size);
        for (const auto& buffer : payload) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            owned_.insert(owned_.end(), data, data + buffer.size());
        }
        bytes_ = owned_;
    }

    [[nodiscard]] std::span<const uint8_t> Bytes() const noexcept {
        return bytes_;
    }

private:
    memory::ByteVector owned_;
    std::span<const uint8_t> bytes_;
};

inline void ValidateFixedUdpDatagram(const buf::MultiBuffer& payload,
                                     const TargetAddress& fixed_target) {
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        return;
    }
    if (!datagram.Valid() || !datagram.target ||
        !datagram.target->IsValid()) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VMess UDP datagram contains missing or mixed endpoints");
    }
    if (!datagram.target->SameEndpoint(fixed_target)) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VMess UDP datagram target differs from the fixed session target");
    }
}

}  // namespace acpp::vmess
