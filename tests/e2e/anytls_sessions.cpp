#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
class Identity : public testing::TestWithParam<std::string> {};
TEST_P(Identity, MonotonicIdsIsolateTargets) {
    const auto mode=GetParam(); Echo target; PanelNode node; TlsContext context(false); TlsSocket client(node.Connect(),context,false); Frames frames(client);
    Authenticate(client,"v=2",UserId); Open(client,7,target.server.Port(),"first-logical-stream");
    frames.Await([&]{return frames.Payload(7)=="first-logical-stream";});
    if(mode=="reuse-completed") {client.Write(AnyTlsFrame(3,7));frames.Barrier();Until([&]{return target.Get(0).closed;});EXPECT_EQ(frames.Count(3,7),0u);}
    const uint32_t sid=mode=="valid-gap"?19:mode=="descending"?6:7;
    Open(client,sid,target.server.Port(),"second-logical-stream");
    if(mode=="valid-gap") {
        frames.Await([&]{return frames.Payload(19)=="second-logical-stream";});client.Write(AnyTlsFrame(3,7)+AnyTlsFrame(3,19));frames.Barrier();
        Until([&]{return target.Count()==2&&target.Get(0).closed&&target.Get(1).closed;});EXPECT_EQ(frames.Count(5),0u);EXPECT_FALSE(frames.closed);EXPECT_EQ(target.Get(1).bytes,"second-logical-stream");
    } else {
        frames.Await([&]{return frames.closed;},3s);EXPECT_TRUE(std::any_of(frames.records.begin(),frames.records.end(),[](const auto& f){return f.command==5&&f.stream==0&&!f.payload.empty();}));
        Until([&]{return target.Get(0).closed;});EXPECT_EQ(target.Count(),1u);
    }
    EXPECT_EQ(target.Get(0).bytes,"first-logical-stream");client.Close();node.Stop();target.server.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,Identity,testing::Values("duplicate-active","reuse-completed","descending","valid-gap"));

class EarlyFin : public testing::TestWithParam<std::string> {};
TEST_P(EarlyFin, PreparationSlotsAreReleasedWithoutFinReply) {
    const auto mode=GetParam();std::string prefix;
    if(mode=="partial-address") prefix=std::string("\1\x7f",2);
    if(mode=="uot1") prefix=Magic(true);
    if(mode=="uot2") prefix=Magic(false)+std::string(1,'\1');
    std::atomic<unsigned> requests=0;
    Server target([&](Socket socket){EXPECT_EQ(socket.ReadExact(8),"request!");++requests;socket.Write("accepted");});
    Node node(true);TlsContext context(false);TlsSocket client(Socket::Connect(node.port),context,false);Frames frames(client);Authenticate(client);
    for(uint32_t sid=1;sid<=128;++sid) client.Write(AnyTlsFrame(1,sid)+(prefix.empty()?std::string{}:AnyTlsFrame(2,sid,prefix))+AnyTlsFrame(3,sid));
    frames.Barrier();EXPECT_EQ(requests,0u);EXPECT_EQ(frames.Count(3),0u);
    Open(client,129,target.Port(),"request!");frames.Await([&]{return frames.Payload(129)=="accepted"&&frames.Count(3,129)==1;});frames.Barrier();EXPECT_EQ(requests,1u);EXPECT_FALSE(frames.closed);
    client.Close();node.Stop();target.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,EarlyFin,testing::Values("syn-only","partial-address","uot1","uot2"));
} // namespace cnode::e2e::sessions
