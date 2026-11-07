#include "anytls_sessions.hpp"
#include <array>

namespace cnode::e2e::sessions {
class StreamParsing:public testing::TestWithParam<std::string>{};
TEST_P(StreamParsing, ByteStreamBoundariesAndIsolation) {
    const auto mode=GetParam();const bool ipv6=mode.find("ipv6")!=std::string::npos,fragmented=mode.find("fragmented")!=std::string::npos;
    Echo target(ipv6?"::1":"127.0.0.1");PanelNode node;TlsContext context(false);TlsSocket client(node.Connect(),context,false);Frames frames(client);Authenticate(client,"v=2",UserId);
    auto address=SocksAddress(target.server.Port(),ipv6?"::1":"127.0.0.1");const auto data=Pattern(60000);
    if(mode.starts_with("uot")) {
        auto udp=Socket::BindUdp();const auto udpPort=udp.Port();std::vector<std::string> packets;PeerThread datagrams([&]{
            for(int i=0;i<2;++i) {Require(Ready(udp.Fd(),5s),"UDP request deadline");std::array<char,65536> bytes{};sockaddr_storage from{};socklen_t length=sizeof(from);auto n=::recvfrom(udp.Fd(),bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&from),&length);Require(n>=0,"UDP receive failed");packets.emplace_back(bytes.data(),static_cast<size_t>(n));Require(::sendto(udp.Fd(),bytes.data(),static_cast<size_t>(n),0,reinterpret_cast<sockaddr*>(&from),length)==n,"UDP echo failed");}
        });
        const bool v1=mode.starts_with("uot1"),connect=mode.find("connect")!=std::string::npos;const auto endpoint=SocksAddress(udpPort).substr(1);const auto prefix=Magic(v1)+(v1?std::string{}:std::string(1,connect?'\1':'\0')+std::string(1,'\1')+endpoint);
        std::string encoded;for(auto packet:{data.substr(0,9000),data.substr(9000,19999)}) encoded+=(connect?std::string{}:std::string(1,'\0')+endpoint)+BigEndian(packet.size(),2)+packet;
        const auto wire=prefix+encoded;client.Write(AnyTlsFrame(1,1));
        if(fragmented) {size_t cut=prefix.size()+9;for(char byte:std::string_view(wire).substr(0,cut))client.Write(AnyTlsFrame(2,1,std::string(1,byte))+AnyTlsFrame(0,0,"padding"));client.Write(AnyTlsFrame(2,1,wire.substr(cut,6000))+AnyTlsFrame(2,1,wire.substr(cut+6000)));}
        else client.Write(AnyTlsFrame(2,1,wire));
        frames.Await([&]{return frames.Payload(1)==encoded;});datagrams.Join();EXPECT_EQ(packets,(std::vector<std::string>{data.substr(0,9000),data.substr(9000,19999)}));
    } else if(mode=="interleaved"||mode=="malformed"||mode=="truncated") {
        client.Write(AnyTlsFrame(1,1)+AnyTlsFrame(2,1,mode=="malformed"?std::string(1,'\xff'):address.substr(0,2))+(mode=="truncated"?AnyTlsFrame(3,1):std::string{}));Open(client,2,target.server.Port(),data);frames.Await([&]{return frames.Payload(2)==data;});EXPECT_EQ(target.Count(),1u);
        if(mode=="interleaved") {client.Write(AnyTlsFrame(2,1,address.substr(2)+data.substr(0,17000)));frames.Await([&]{return frames.Payload(1)==data.substr(0,17000);});EXPECT_EQ(target.Count(),2u);}
        else if(mode=="malformed") frames.Await([&]{return frames.Count(3,1)>0;});else EXPECT_EQ(frames.Count(3,1),0u);
    } else {
        client.Write(AnyTlsFrame(1,1));if(fragmented) {for(char byte:std::string_view(address).substr(0,address.size()-1))client.Write(AnyTlsFrame(2,1,std::string(1,byte))+AnyTlsFrame(2,1));client.Write(AnyTlsFrame(2,1,address.substr(address.size()-1)+data.substr(0,17000))+AnyTlsFrame(2,1,data.substr(17000)));}
        else client.Write(AnyTlsFrame(2,1,address+data));frames.Await([&]{return frames.Payload(1)==data;});EXPECT_EQ(target.Count(),1u);EXPECT_EQ(target.Get(0).bytes,data);
    }
    frames.Barrier();EXPECT_FALSE(frames.closed);EXPECT_EQ(frames.Count(5),0u);client.Close();node.Stop();target.server.Stop();
}
INSTANTIATE_TEST_SUITE_P(All,StreamParsing,testing::Values("tcp-coalesced","tcp-fragmented","tcp-ipv6-coalesced","tcp-ipv6-fragmented","interleaved","malformed","truncated","uot1-coalesced","uot1-fragmented","uot2-connect-coalesced","uot2-connect-fragmented","uot2-packet-coalesced","uot2-packet-fragmented"));
} // namespace cnode::e2e::sessions
