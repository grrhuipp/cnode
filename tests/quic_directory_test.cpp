#include <gtest/gtest.h>

#include "quic_handoff.hpp"

#include <array>
#include <stdexcept>

using namespace ::transport::internet::hysteria;

namespace {
void Require(bool condition) {
    if (!condition) throw std::runtime_error("QUIC CID directory invariant failed");
}

TEST(QuicDirectory, PublicationIsExclusiveAndNamespaceScoped) {
    ::net::io_context io;
    auto& directory = ::net::use_service<QuicDirectory>(io);
    auto first = std::make_shared<QuicOwnership>();
    auto second = std::make_shared<QuicOwnership>();
    auto isolated = std::make_shared<QuicOwnership>();
    const std::array<uint8_t, 4> a{1, 2, 3, 4}, b{5, 6, 7, 8};
    const ConnectionId cid_a(a.data(), a.size()), cid_b(b.data(), b.size());

    Require(directory.Publish("listener-a", {cid_a}, first));
    Require(directory.Publish("listener-a", {cid_a, cid_b}, first));
    Require(directory.Find("listener-a", cid_b) == first);
    Require(!directory.Publish("listener-a", {cid_b}, second));
    Require(directory.Find("listener-a", cid_b) == first);
    Require(directory.Publish("listener-b", {cid_b}, isolated));
    Require(directory.Find("listener-b", cid_b) == isolated);
    Require(directory.Publish("listener-a", {cid_b}, first));
    Require(!directory.Find("listener-a", cid_a));
    Require(directory.Publish("listener-a", {cid_a}, second));
    Require(!directory.Publish("listener-a", {cid_a, cid_b}, second));
    Require(directory.Find("listener-a", cid_a) == second);
    Require(directory.Find("listener-a", cid_b) == first);
}

TEST(QuicDirectory, RetirementWinsAgainstQueuedPublication) {
    ::net::io_context io;
    auto& directory = ::net::use_service<QuicDirectory>(io);
    auto original = std::make_shared<QuicOwnership>();
    auto replacement = std::make_shared<QuicOwnership>();
    const std::array<uint8_t, 4> bytes{9, 10, 11, 12};
    const ConnectionId cid(bytes.data(), bytes.size());

    Require(directory.Publish("listener", {cid}, original));
    original->retired.store(true);
    Require(!directory.Find("listener", cid));
    QuicDirectory::Retirement retirement(directory, "listener", original);
    retirement.Invoke();
    Require(directory.Publish("listener", {cid}, replacement));
    Require(!directory.Publish("listener", {cid}, original));
    retirement.Invoke();
    Require(directory.Find("listener", cid) == replacement);
}
} // namespace

