#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
struct PoolCase {const char* name;unsigned minimum;const char* mode;Json timeouts;};
class PoolLifecycle:public testing::TestWithParam<PoolCase>{};
TEST_P(PoolLifecycle, EvictsReusesAndCancelsBlockedDirections) {
    const auto c=GetParam();SCOPED_TRACE(c.name);const std::string mode=c.mode;const unsigned initial=c.minimum?2:1;const bool blocked=mode=="stalled_write"||mode=="write_timeout"||mode=="alert_during_write";
    TlsContext context(true);std::atomic<unsigned> accepted=0,closed=0,finished=0,trickles=0;
    Server peer([&](Socket socket){++accepted;TlsSocket tls(std::move(socket),context,true);ReadAnyTlsAuthentication(tls,"secret");std::map<uint32_t,std::string> requests;bool stalled=false;uint32_t trickleSid=0;auto next=std::chrono::steady_clock::now();AnyTlsRecord f;
        for(;;) {
            if(trickleSid) {if(std::chrono::steady_clock::now()>=next){tls.Write(AnyTlsFrame(2,trickleSid,"trickle"));++trickles;next=std::chrono::steady_clock::now()+100ms;}if(!SSL_pending(tls.Get())&&!Ready(tls.Fd(),20ms))continue;}
            bool hasFrame;
            try {hasFrame=Next(tls,f);}
            catch(const std::system_error& error) {
                // Cancelling an in-flight frame retires the physical session abortively.
                // Only the injected blocked-write cases may terminate this read with RST.
                if(!blocked||!stalled||error.code()!=std::errc::connection_reset||
                   !std::string_view(error.what()).starts_with("SSL_read:"))throw;
                break;
            }
            if(!hasFrame)break;
            if(f.command==2&&blocked&&!stalled) {stalled=true;int small=4096;Require(::setsockopt(tls.Fd(),SOL_SOCKET,SO_RCVBUF,&small,sizeof(small))==0,"peer receive buffer");tls.Write(AnyTlsFrame(2,f.stream,"anytls-pool-reply"));std::this_thread::sleep_for(600ms);
                if(mode=="stalled_write")tls.Write(AnyTlsFrame(3,f.stream));if(mode=="alert_during_write")tls.Write(AnyTlsFrame(5,f.stream,"rejected while upload is blocked"));std::this_thread::sleep_for(1400ms);
            } else if(f.command==2&&!stalled) {auto& request=requests[f.stream];request+=f.payload;if(request==SocksAddress(443)+"pool-probe") {++finished;Until([&]{return finished.load()>=initial;});tls.Write(AnyTlsFrame(2,f.stream,"anytls-pool-reply")+(mode=="complete"?AnyTlsFrame(3,f.stream):std::string{}));if(mode=="trickle_no_fin"){trickleSid=f.stream;next=std::chrono::steady_clock::now()+100ms;}}}
            else if(f.command==3&&f.stream==trickleSid)trickleSid=0;else if(f.command==8)tls.Write(AnyTlsFrame(9,f.stream));
        } ++closed;
    });
    Node node(false,peer.Port(),c.timeouts,c.minimum,1);auto request=[&]{auto app=node.Application("pool-probe");EXPECT_EQ(app.ReadExact(2+17),std::string("\0\0",2)+"anytls-pool-reply");
        if(mode=="trickle_no_fin"){std::this_thread::sleep_for(600ms);app.ShutdownWrite();}
        if(blocked) {std::atomic<size_t> sent=0;PeerThread upload([&]{const std::string chunk(65536,'x');try{for(int i=0;i<1024;++i){app.Write(chunk,5s);sent+=chunk.size();}}catch(const std::system_error& error) {if(error.code().value()!=ECONNRESET&&error.code().value()!=EPIPE)throw;}});Drain(app,5s,true);upload.Join();EXPECT_LT(sent.load(),64u*1024u*1024u);}
        else Drain(app,5s);
    };
    const auto started=std::chrono::steady_clock::now();std::vector<std::unique_ptr<PeerThread>> clients;for(unsigned i=0;i<initial;++i)clients.push_back(std::make_unique<PeerThread>(request));for(auto& client:clients)client->Join();const auto elapsed=std::chrono::steady_clock::now()-started;
    EXPECT_EQ(accepted.load(),initial);if(!blocked)EXPECT_EQ(finished.load(),initial);if(mode!="complete"){EXPECT_GE(elapsed,500ms);EXPECT_LT(elapsed,4s);}if(mode=="stalled_write"||mode=="alert_during_write")EXPECT_LT(elapsed,1800ms);if(mode=="trickle_no_fin")EXPECT_GE(trickles.load(),3u);
    std::this_thread::sleep_for(3500ms);EXPECT_EQ(accepted.load()-closed.load(),c.minimum);if(c.minimum){request();EXPECT_EQ(accepted.load(),initial);}node.Stop();peer.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,PoolLifecycle,testing::ValuesIn(std::vector<PoolCase>{
    {"minimum-zero",0,"complete",Json::object()},{"minimum-one",1,"complete",Json::object()},
    {"idle-without-fin",0,"no_fin",{{"connIdle",1}}},{"local-close-during-trickle",0,"trickle_no_fin",{{"connIdle",10}}},
    {"remote-fin-during-write",0,"stalled_write",{{"write",30},{"connIdle",30}}},{"write-timeout",0,"write_timeout",{{"write",1}}},
    {"alert-during-write",0,"alert_during_write",{{"write",30},{"connIdle",30}}},{"reuse-after-deadline",1,"complete",{{"downlinkOnly",1},{"connIdle",1},{"write",1}}}
}),[](const testing::TestParamInfo<PoolCase>& info) {
    std::string name=info.param.name;std::replace(name.begin(),name.end(),'-','_');return name;
});
} // namespace cnode::e2e::sessions
