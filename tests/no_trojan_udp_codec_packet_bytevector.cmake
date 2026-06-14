file(READ "${PROJECT_SOURCE_DIR}/src/proxy/trojan/trojan_codec.hpp" codec_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/trojan/inbound/trojan_inbound.cpp" inbound_source)

if(codec_header MATCHES "struct[ \t\r\n]+UdpPacket[^{]*\\{[^}]*memory::ByteVector[ \t\r\n]+payload[ \t\r\n]*;")
    message(FATAL_ERROR
        "Trojan UDP decode result must not own ByteVector payload; hand off payload as a view into Worker Buffer storage")
endif()

if(inbound_source MATCHES "pkt\\.payload\\.assign\\(")
    message(FATAL_ERROR
        "Trojan UDP framer must not copy decoded payload into ByteVector before Buffer ownership handoff")
endif()
