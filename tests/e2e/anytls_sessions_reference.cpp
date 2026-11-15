#include "anytls_sessions.hpp"
#include "reference_support.hpp"

namespace cnode::e2e::sessions {
class ReferenceFin : public testing::TestWithParam<std::tuple<bool, bool>> {};
TEST_P(ReferenceFin, PinnedUnmodifiedReferenceHasIdenticalClosureSemantics) {
    const auto [server, remote] = GetParam();
    const std::string binary = server ? CNODE_REFERENCE_ANYTLS_SERVER : CNODE_REFERENCE_ANYTLS_CLIENT;
    reference::VerifyAnyTls(binary, server ? "server" : "client");
    reference::BinaryGuard guard({Binary(), binary});
    if (server) ServerFin(remote, binary);
    else ClientFin(remote, binary);
    guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All, ReferenceFin, testing::Combine(testing::Bool(), testing::Bool()));
class ReferenceSessionEnd : public testing::TestWithParam<bool> {};
TEST_P(ReferenceSessionEnd, PinnedUnmodifiedClientDeliversFinishedStreamAcrossSessionEnd) {
    const std::string binary = CNODE_REFERENCE_ANYTLS_CLIENT;
    reference::VerifyAnyTls(binary, "client");
    reference::BinaryGuard guard({Binary(), binary});
    ClientFinThenSessionEnd(GetParam(), binary);
    guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All, ReferenceSessionEnd, testing::Bool(),
                         [](const auto& info) { return info.param ? "Alert" : "TransportClose"; });
} // namespace cnode::e2e::sessions
