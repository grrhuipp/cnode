#include <stdexcept>
#include <gtest/gtest.h>

#include "vless_encryption_runtime.hpp"
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>

namespace {
void Check(bool ok, const char* what) {
    if (!ok) { std::cerr << what << '\n'; ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed"); }
}
}
TEST(VlessTicketStore, Contract) {
    using namespace ::vless;
    using namespace std::chrono_literals;
    const auto now = std::chrono::steady_clock::time_point{} + 100s;
    std::array<uint8_t, 16> ticket{};
    std::array<uint8_t, 16> alice{};
    std::array<uint8_t, 16> bob{};
    bob[0] = 1;
    VlessEncryptionPfsKey pfs;
    pfs.bytes[0] = 42;
    VlessEncryptionNfsKey nfs;
    nfs.bytes[0] = 7;
    VlessEncryptionServerTicketStore owner;
    VlessEncryptionServerTicketStore other_inbound;
    owner.Store(ticket, pfs, 60, now);
    Check(!owner.Lookup(ticket, nfs, now), "unauthenticated ticket accepted");
    Check(owner.BindIdentity(ticket, alice, now), "identity binding failed");
    Check(!owner.BindIdentity(ticket, bob, now), "ticket identity replaced");
    auto accepted = owner.Lookup(ticket, nfs, now);
    Check(accepted && accepted->identity == alice && accepted->pfs_key.bytes[0] == 42,
          "ticket identity or key changed");
    Check(!owner.Lookup(ticket, nfs, now), "same-worker replay accepted");
    Check(!other_inbound.Lookup(ticket, nfs, now), "cross-inbound ticket accepted");
    // Duplicate Store cannot reset the replay cache or extend ticket lifetime.
    VlessEncryptionPfsKey replacement;
    replacement.bytes[0] = 99;
    owner.Store(ticket, replacement, 3600, now + 1s);
    Check(!owner.Lookup(ticket, nfs, now + 1s), "duplicate Store reset replay history");
    nfs.bytes[0] = 8;
    accepted = owner.Lookup(ticket, nfs, now + 59s);
    Check(accepted && accepted->pfs_key.bytes[0] == 42, "duplicate Store replaced PFS key");
    nfs.bytes[0] = 9;
    Check(!owner.Lookup(ticket, nfs, now + 60s), "ticket accepted exactly at expiration");
    Check(!owner.BindIdentity(ticket, alice, now + 60s), "expired ticket rebound");
    // Capacity eviction rejects the old ticket, never resurrects it without its
    // replay keys. All mutations remain within the owner executor.
    VlessEncryptionServerTicketStore bounded;
    for (size_t i = 0; i < 1025; ++i) {
        ticket[0] = static_cast<uint8_t>(i >> 8);
        ticket[1] = static_cast<uint8_t>(i);
        bounded.Store(ticket, pfs, 60, now);
        Check(bounded.BindIdentity(ticket, alice, now), "capacity insertion failed");
    }
    ticket = {};
    Check(!bounded.Lookup(ticket, nfs, now), "evicted ticket still accepted");
}
