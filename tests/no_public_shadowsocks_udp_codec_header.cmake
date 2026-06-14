set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(PUBLIC_HEADER "${ROOT}/include/acppnode/proxy/shadowsocks/ss_udp.hpp")

if(EXISTS "${PUBLIC_HEADER}")
    message(FATAL_ERROR
        "Shadowsocks UDP codec must remain protocol-private, not a public include header: ${PUBLIC_HEADER}")
endif()
