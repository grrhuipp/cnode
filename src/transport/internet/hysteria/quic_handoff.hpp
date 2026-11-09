#pragma once

#include <ngtcp2/ngtcp2.h>
#include <linux/filter.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>

namespace transport::internet::hysteria {
class Connection;

inline constexpr size_t kServerConnectionIdLength = 18;
inline constexpr uint8_t kServerCidMagic0 = 0xa5;
inline constexpr uint8_t kServerCidMagic1 = 0x5a;
inline constexpr uint16_t kServerCidMagicWord =
    (static_cast<uint16_t>(kServerCidMagic0) << 8) | kServerCidMagic1;

inline void EncodeWorkerServerCid(ngtcp2_cid& cid, size_t length, uint32_t worker_id) noexcept {
    cid.datalen = length;
    if (length >= 3) {
        cid.data[0] = kServerCidMagic0;
        cid.data[1] = kServerCidMagic1;
        cid.data[2] = static_cast<uint8_t>(worker_id);
    }
}

[[nodiscard]] inline bool AttachQuicReuseportBpf(int fd, uint32_t worker_count) noexcept {
    const uint32_t count = std::max<uint32_t>(1, worker_count);
    // Fallback hashes Initial DCID[0..3] at payload[6..9] for uniform distribution.
    std::array<sock_filter, 15> insns{{
        // 0: A = payload[0] (QUIC Header flags)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 0},
        // 1: if (A & 0x80) != 0 goto 6 (Long Header)
        {BPF_JMP | BPF_JSET | BPF_K, 4, 0, 0x80},
        // 2: Short Header: A = payload[1..2] (DCID[0..1])
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 1},
        // 3: if A != kServerCidMagicWord goto 12 (fallback hash)
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 8, kServerCidMagicWord},
        // 4: A = payload[3] (DCID[2] == worker_id)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 3},
        // 5: jump to 11 (range check)
        {BPF_JMP | BPF_JA, 0, 0, 5},
        // 6: Long Header: A = payload[5] (DCID length)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 5},
        // 7: if A != kServerConnectionIdLength goto 12 (fallback hash)
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 4, static_cast<uint32_t>(kServerConnectionIdLength)},
        // 8: A = payload[6..7] (Long Header DCID[0..1])
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 6},
        // 9: if A != kServerCidMagicWord goto 12 (fallback hash)
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 2, kServerCidMagicWord},
        // 10: A = payload[8] (Long Header DCID[2] == worker_id)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 8},
        // 11: if A >= count goto 12 (fallback hash) else goto 14 (return A)
        {BPF_JMP | BPF_JGE | BPF_K, 0, 2, count},
        // 12: fallback: A = payload[6..9] (Initial random DCID prefix)
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 6},
        // 13: A = A % count
        {BPF_ALU | BPF_MOD | BPF_K, 0, 0, count},
        // 14: return A
        {BPF_RET | BPF_A, 0, 0, 0},
    }};
    sock_fprog prog{
        .len = static_cast<unsigned short>(insns.size()),
        .filter = insns.data(),
    };
    return ::setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog)) == 0;
}

struct ConnectionId {
    std::array<uint8_t, NGTCP2_MAX_CIDLEN> bytes{};
    uint8_t size = 0;
    explicit ConnectionId(const ngtcp2_cid& cid) noexcept
        : ConnectionId(cid.data, cid.datalen) {}
    ConnectionId(const uint8_t* data, size_t length) noexcept
        : size(static_cast<uint8_t>(length)) {
        std::copy_n(data, length, bytes.begin());
    }
    bool operator==(const ConnectionId&) const noexcept = default;
};

struct ConnectionIdHash {
    size_t operator()(const ConnectionId& id) const noexcept {
        size_t hash = 1469598103934665603ULL;
        for (size_t i = 0; i < id.size; ++i) {
            hash ^= id.bytes[i];
            hash *= 1099511628211ULL;
        }
        return hash ^ id.size;
    }
};

struct QuicOwnership {
    std::weak_ptr<Connection> connection;
    bool retired = false;
    ngtcp2_tstamp expiry = std::numeric_limits<ngtcp2_tstamp>::max();
};

} // namespace transport::internet::hysteria
