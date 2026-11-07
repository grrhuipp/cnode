#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
TEST(AnyTlsFin, InboundRemoteFin) {ServerFin(true);}
TEST(AnyTlsFin, InboundLocalEof) {ServerFin(false);}
TEST(AnyTlsFin, OutboundRemoteFin) {ClientFin(true);}
TEST(AnyTlsFin, OutboundLocalEof) {ClientFin(false);}
class OpeningFin:public testing::TestWithParam<std::tuple<bool,bool>>{};
TEST_P(OpeningFin, ClosesBeforeSynackAndPreservesOpeningWriteOrder) {
    const auto [padding,withPayload]=GetParam();const auto expected=withPayload?Pattern(251*32):std::string{};
    TlsContext context(true);std::atomic<unsigned> connections=0,finReplies=0,hearts=0;std::atomic<size_t> paddingBytes=0,latePayload=0;std::mutex mutex;std::vector<uint32_t> ids;std::chrono::steady_clock::time_point finAt;
    Server peer([&](Socket socket){++connections;TlsSocket tls(std::move(socket),context,true);ReadAnyTlsAuthentication(tls,"secret");std::map<uint32_t,std::string> requests;bool finSent=false;AnyTlsRecord f;
        while(Next(tls,f)) {
            if(f.command==4)tls.Write(AnyTlsFrame(10,0,"v=2"));
            else if(f.command==1) {{std::lock_guard lock(mutex);ids.push_back(f.stream);}if(f.stream!=2)tls.Write(AnyTlsFrame(7,f.stream));}
            else if(f.command==2) {requests[f.stream]+=f.payload;if(f.stream==2){if(!finSent){if(padding)EXPECT_EQ(requests[2],SocksAddress(443));finAt=std::chrono::steady_clock::now();finSent=true;tls.Write((expected.empty()?std::string{}:AnyTlsFrame(2,2,expected))+AnyTlsFrame(3,2)+AnyTlsFrame(8,0));if(padding)std::this_thread::sleep_for(400ms);}else latePayload+=f.payload.size();}
                else if(requests[f.stream]==SocksAddress(443)+"request!") {if(padding&&f.stream==1){std::string scheme="stop=4\n3=";for(int i=0;i<4096;++i){if(i)scheme+=',';scheme+="8000-8001";}scheme+='\n';tls.Write(AnyTlsFrame(6,0,scheme));}tls.Write(AnyTlsFrame(2,f.stream,"accepted")+AnyTlsFrame(3,f.stream));}}
            else if(f.command==0&&finSent)paddingBytes+=f.payload.size();else if(f.command==3&&f.stream==2)++finReplies;else if(f.command==9)++hearts;else if(f.command==8)tls.Write(AnyTlsFrame(9,0));
        }
    });
    Node node(false,peer.Port());{auto warmup=node.Application();EXPECT_EQ(Drain(warmup),std::string("\0\0",2)+"accepted");}
    auto app=node.Application();EXPECT_EQ(Drain(app,6s),std::string("\0\0",2)+expected);auto closedAt=std::chrono::steady_clock::now();Until([&]{return hearts.load()>0;},2s);
    EXPECT_LT(closedAt-finAt,2s);if(padding)EXPECT_GE(paddingBytes.load(),30u*1024u*1024u);EXPECT_EQ(latePayload.load(),0u);EXPECT_EQ(finReplies.load(),0u);
    auto recovery=node.Application();EXPECT_EQ(Drain(recovery),std::string("\0\0",2)+"accepted");EXPECT_EQ(connections.load(),1u);{std::lock_guard lock(mutex);EXPECT_EQ(ids,(std::vector<uint32_t>{1,2,3}));}
    node.Stop();peer.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,OpeningFin,testing::Combine(testing::Bool(),testing::Bool()));
} // namespace cnode::e2e::sessions
