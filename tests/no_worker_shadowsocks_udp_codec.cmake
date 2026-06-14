file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

set(forbidden_patterns
    "proxy/shadowsocks/ss_udp\\.hpp"
    "proxy/shadowsocks/inbound/ss_inbound\\.hpp"
    "proxy::shadowsocks::inbound::Handler"
    "ss::EncodeUdpPacketTo"
    "ss::DecodeUdpPacket"
)

foreach(pattern IN LISTS forbidden_patterns)
    if(worker_cpp MATCHES "${pattern}")
        message(FATAL_ERROR
            "Worker must not directly use Shadowsocks UDP codec; matched '${pattern}'")
    endif()
endforeach()
