set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(SCAN_FILES
    "${ROOT}/include/acppnode/app/relay.hpp"
    "${ROOT}/src/app/relay_udp.cpp"
    "${ROOT}/src/common/mux/mux_relay.cpp"
)

set(FORBIDDEN_PATTERNS
    "VMess"
    "Trojan"
    "Shadowsocks"
    "TrojanCodec"
    "SsAeadCipher"
)

foreach(file IN LISTS SCAN_FILES)
    if(NOT EXISTS "${file}")
        continue()
    endif()
    file(READ "${file}" content)
    foreach(pattern IN LISTS FORBIDDEN_PATTERNS)
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR
                "relay must remain protocol-agnostic: ${file} matches ${pattern}")
        endif()
    endforeach()
endforeach()
