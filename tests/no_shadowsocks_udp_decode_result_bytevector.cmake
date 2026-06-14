file(READ "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/ss_udp.hpp" codec_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/inbound/ss_inbound.cpp" inbound_source)

if(codec_header MATCHES "struct[ \t\r\n]+SsUdpDecodeResult[^{]*\\{[^}]*memory::ByteVector[ \t\r\n]+payload[ \t\r\n]*;")
    message(FATAL_ERROR
        "Shadowsocks UDP decode result must not own ByteVector payload; use MultiBuffer ownership")
endif()

if(codec_header MATCHES "payload_offset|payload_size")
    message(FATAL_ERROR
        "Shadowsocks UDP decode result must not expose offset/size into decoded ByteVector storage")
endif()

if(inbound_source MATCHES "decoded->payload\\.data\\(\\)[ \t\r\n]*\\+[ \t\r\n]*payload_offset")
    message(FATAL_ERROR
        "Shadowsocks inbound UDP must not re-slice ByteVector decode payload before MultiBuffer handoff")
endif()
