set(files
    "${PROJECT_SOURCE_DIR}/src/proxy/trojan/trojan_codec.hpp"
    "${PROJECT_SOURCE_DIR}/src/proxy/trojan/trojan_codec.cpp"
    "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/ss_udp.hpp"
    "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/ss_udp.cpp"
)

foreach(path IN LISTS files)
    file(READ "${path}" content)
    if(content MATCHES "memory::ByteVector[ \t\r\n]+(TrojanCodec::)?Encode(UdpPacket|Request)[ \t\r\n]*\\(")
        message(FATAL_ERROR
            "Protocol hot-path encoders must not expose unused ByteVector-returning builders; use Encode*To caller scratch")
    endif()
endforeach()
