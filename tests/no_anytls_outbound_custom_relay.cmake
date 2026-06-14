file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp" outbound_source)

if(NOT outbound_source MATCHES "DoRelayLink")
    message(FATAL_ERROR "AnyTLS outbound must use common relay helpers instead of protocol-local relay loops")
endif()

foreach(pattern IN ITEMS
    "auto[ \t\r\n]+upload[ \t\r\n]*="
    "auto[ \t\r\n]+download[ \t\r\n]*="
    "co_await[ \t\r\n]*\\([ \t\r\n]*upload\\(\\)[ \t\r\n]*&&[ \t\r\n]*download\\(\\)[ \t\r\n]*\\)")
    if(outbound_source MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS outbound must not implement a protocol-local bidirectional relay loop: ${pattern}")
    endif()
endforeach()
