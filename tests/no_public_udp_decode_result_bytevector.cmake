file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_handler.hpp" content)

if(content MATCHES "struct[ \t\r\n]+UdpDecodeResult[^{]*\\{[^}]*memory::ByteVector[ \t\r\n]+payload[ \t\r\n]*;")
    message(FATAL_ERROR
        "UdpDecodeResult must not expose ByteVector payload storage; use move-only Buffer/MultiBuffer ownership")
endif()
