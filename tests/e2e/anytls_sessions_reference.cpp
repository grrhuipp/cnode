#include "anytls_sessions.hpp"
#include "reference_support.hpp"

namespace cnode::e2e::sessions {
class ReferenceFin:public testing::TestWithParam<std::tuple<bool,bool>>{};
TEST_P(ReferenceFin, PinnedUnmodifiedReferenceHasIdenticalClosureSemantics) {
    const auto [server,remote]=GetParam();const std::string binary=server?CNODE_REFERENCE_ANYTLS_SERVER:CNODE_REFERENCE_ANYTLS_CLIENT;
    reference::VerifyAnyTls(binary,server?"server":"client");reference::BinaryGuard guard({Binary(),binary});
    if(server)ServerFin(remote,binary);else ClientFin(remote,binary);guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All,ReferenceFin,testing::Combine(testing::Bool(),testing::Bool()));
} // namespace cnode::e2e::sessions
