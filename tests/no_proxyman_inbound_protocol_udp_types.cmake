set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(files
    "${ROOT}/include/acppnode/app/proxyman/inbound/udp_handler.hpp"
)

set(FORBIDDEN_PATTERNS
    "acppnode/proxy/shadowsocks/ss_udp\\.hpp"
    "SsUdpDecodeResult"
    "SsCipherInfo"
    "KeyBytes"
    "::acpp::ss::"
)

foreach(file IN LISTS files)
    file(READ "${file}" content)
    foreach(pattern IN LISTS FORBIDDEN_PATTERNS)
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR
                "proxyman inbound public API must not expose Shadowsocks UDP codec types: ${file} matches ${pattern}")
        endif()
    endforeach()
endforeach()
