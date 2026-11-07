#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
std::string MuxFrame(uint8_t status,std::string_view payload={},uint16_t port=0) {
    auto metadata=BigEndian(1,2)+std::string{static_cast<char>(status),static_cast<char>(!payload.empty())};
    if(port)metadata+=std::string(1,'\1')+BigEndian(port,2)+std::string("\1\x7f\0\0\1",5);
    return BigEndian(metadata.size(),2)+metadata+(payload.empty()?std::string{}:BigEndian(payload.size(),2)+std::string(payload));
}
class SubstreamCancellation:public testing::TestWithParam<std::tuple<bool,bool>>{};
TEST_P(SubstreamCancellation, RateLimitedQueueDrainsOnlyOnLogicalFin) {
    const auto [anytls,terminate]=GetParam();std::mutex mutex;std::string received;std::atomic<bool> closed=false;std::chrono::steady_clock::time_point closedAt;
    Server target([&](Socket socket){try{for(;;){auto bytes=socket.Read();if(bytes.empty())break;std::lock_guard lock(mutex);received+=bytes;}}catch(const std::system_error& error){if(error.code().value()!=ECONNRESET)throw;}closedAt=std::chrono::steady_clock::now();closed=true;});
    PanelNode node(anytls);TlsContext context(false);std::unique_ptr<TlsSocket> tls;Socket plain;
    if(anytls)tls=std::make_unique<TlsSocket>(node.Connect(),context,false);else plain=node.Connect();
    auto send=[&](std::string_view bytes){if(tls)tls->Write(bytes);else plain.Write(bytes);};const std::string chunk(60000,'R');
    if(anytls){Authenticate(*tls,"v=2",UserId);send(AnyTlsFrame(1,1)+AnyTlsFrame(2,1,SocksAddress(target.Port()))+AnyTlsFrame(2,1,chunk)+AnyTlsFrame(2,1,chunk));}
    else send(std::string(1,'\0')+UuidBytes()+std::string("\0\3",2)+MuxFrame(1,chunk,target.Port())+MuxFrame(2,chunk));
    auto size=[&]{std::lock_guard lock(mutex);return received.size();};Until([&]{return size()>=120000;});ASSERT_EQ(size(),120000u);
    send(anytls?AnyTlsFrame(2,1,chunk):MuxFrame(2,chunk));std::this_thread::sleep_for(50ms);EXPECT_EQ(size(),120000u);EXPECT_FALSE(closed);
    const auto start=std::chrono::steady_clock::now();send(anytls?AnyTlsFrame(terminate?99:3,1):(terminate?std::string("\0\3\0\1\2\0",6):MuxFrame(3)));
    Until([&]{return closed.load();},2s);const auto elapsed=closedAt-start;{std::lock_guard lock(mutex);EXPECT_EQ(received,std::string(terminate?120000:180000,'R'));}
    if(terminate){EXPECT_GE(elapsed,0ms);EXPECT_LT(elapsed,250ms);}else{EXPECT_GT(elapsed,200ms);EXPECT_LT(elapsed,1500ms);}
    if(tls)tls->Close();else plain.Close();node.Stop();target.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,SubstreamCancellation,testing::Combine(testing::Bool(),testing::Bool()));
} // namespace cnode::e2e::sessions
