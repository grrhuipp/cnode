file(READ "${PROJECT_SOURCE_DIR}/src/proxy/trojan/trojan_codec.hpp" codec_header)

if(codec_header MATCHES "struct[ \t\r\n]+TrojanRequest[^{]*\\{[^}]*memory::ByteVector[ \t\r\n]+payload[ \t\r\n]*;")
    message(FATAL_ERROR
        "TrojanRequest must not own first-packet ByteVector payload; inbound keeps leftover bytes in InitialPayload/Buffer ownership")
endif()
