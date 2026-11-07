#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
class HandshakeBudget:public testing::TestWithParam<std::string>{};
TEST_P(HandshakeBudget, AbsoluteDeadlineAndAdmissionCapacity) {
    const auto mode=GetParam();const bool capacity=mode.starts_with("capacity");const unsigned version=mode=="capacity-v1"?1:2;
    Echo target;PanelNode node(true,{{"handshake",capacity?3:1},{"connIdle",3},{"uplinkOnly",2},{"downlinkOnly",2}});TlsContext context(false);TlsSocket client(node.Connect(),context,false);Frames frames(client);Authenticate(client,version==1?"v=1":"v=2",UserId);
    const auto start=std::chrono::steady_clock::now();
    auto activityUntil=[&](const std::function<bool()>& done,Milliseconds timeout){const auto end=std::chrono::steady_clock::now()+timeout;auto next=std::chrono::steady_clock::now();while(!done()) {
        Require(!frames.closed&&std::chrono::steady_clock::now()<end,"budget observation failed");if(std::chrono::steady_clock::now()>=next) {client.Write(AnyTlsFrame(version==2?8:0,0));if(mode=="trickle")client.Write(AnyTlsFrame(2,1,"a"));next=std::chrono::steady_clock::now()+100ms;}
        if(SSL_pending(client.Get())||Ready(client.Fd(),20ms))frames.One(500ms);
    }};
    if(capacity) {
        for(uint32_t sid=1;sid<=128;++sid) {if(mode=="capacity-live")Open(client,sid,target.server.Port(),"proof");else client.Write(AnyTlsFrame(1,sid));}
        if(mode=="capacity-live") {activityUntil([&]{for(uint32_t sid=1;sid<=128;++sid)if(frames.Payload(sid)!="proof")return false;return true;},2s);EXPECT_EQ(target.Count(),128u);}
        client.Write(AnyTlsFrame(1,129));activityUntil([&]{return frames.Count(3,129)>0;},500ms);
        const bool error=std::any_of(frames.records.begin(),frames.records.end(),[](const auto& f){return f.command==7&&f.stream==129&&!f.payload.empty();});EXPECT_EQ(error,version==2);EXPECT_FALSE(frames.closed);
        if(mode=="capacity-live") {client.Write(AnyTlsFrame(2,128,"-still-live"));frames.Await([&]{return frames.Payload(128)=="proof-still-live";});}
        else {client.Write(AnyTlsFrame(3,1));if(version==2)frames.Barrier();Open(client,130,target.server.Port(),"new-slot");frames.Await([&]{return frames.Payload(130)=="new-slot";});EXPECT_EQ(frames.Count(3,1),0u);EXPECT_EQ(target.Count(),1u);}
    } else if(mode=="prepared-survives") {
        Open(client,1,target.server.Port(),"before");frames.Await([&]{return frames.Payload(1)=="before";});activityUntil([&]{return std::chrono::steady_clock::now()-start>=1350ms;},1600ms);
        client.Write(AnyTlsFrame(2,1,"-after"));frames.Await([&]{return frames.Payload(1)=="before-after";});EXPECT_EQ(frames.Count(3,1),0u);EXPECT_EQ(target.Count(),1u);
    } else {
        client.Write(AnyTlsFrame(1,1));if(mode=="half-address")client.Write(AnyTlsFrame(2,1,SocksAddress(target.server.Port()).substr(0,2)));if(mode=="trickle")client.Write(AnyTlsFrame(2,1,std::string("\3\x3f",2)));if(mode=="uot1"||mode=="uot2")client.Write(AnyTlsFrame(2,1,Magic(mode=="uot1")));
        activityUntil([&]{return frames.Count(3,1)>0;},1700ms);auto elapsed=std::chrono::steady_clock::now()-start;EXPECT_GE(elapsed,700ms);EXPECT_LE(elapsed,1600ms);EXPECT_EQ(target.Count(),0u);EXPECT_FALSE(frames.closed);
        client.Write(AnyTlsFrame(2,1,SocksAddress(target.server.Port())+"late"));Open(client,2,target.server.Port(),"new-stream");frames.Await([&]{return frames.Payload(2)=="new-stream";});EXPECT_EQ(target.Count(),1u);EXPECT_EQ(target.Get(0).bytes,"new-stream");
    }
    if(version==2)frames.Barrier();EXPECT_FALSE(frames.closed);EXPECT_EQ(frames.Count(5),0u);client.Close();node.Stop();target.server.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,HandshakeBudget,testing::Values("syn-only","half-address","trickle","uot1","uot2","prepared-survives","capacity-v1","capacity-v2","capacity-live"));
} // namespace cnode::e2e::sessions
