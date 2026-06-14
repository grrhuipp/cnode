set(ROOT "${PROJECT_SOURCE_DIR}")
set(PROTOCOL_OUTBOUND_FILES
    "${ROOT}/src/proxy/vmess/outbound/vmess_outbound.cpp"
    "${ROOT}/src/proxy/shadowsocks/outbound/ss_outbound.cpp"
)

foreach(file IN LISTS PROTOCOL_OUTBOUND_FILES)
    file(READ "${file}" source)

    if(NOT source MATCHES "DoRelayLink")
        message(FATAL_ERROR "${file} must use common relay helpers")
    endif()

    foreach(pattern IN ITEMS
        "auto[ \t\r\n]+upload[ \t\r\n]*="
        "auto[ \t\r\n]+download[ \t\r\n]*="
        "co_await[ \t\r\n]*\\([ \t\r\n]*upload\\(\\)[ \t\r\n]*&&[ \t\r\n]*download\\(\\)[ \t\r\n]*\\)")
        if(source MATCHES "${pattern}")
            message(FATAL_ERROR
                "${file} must not implement a protocol-local bidirectional relay loop: ${pattern}")
        endif()
    endforeach()
endforeach()
