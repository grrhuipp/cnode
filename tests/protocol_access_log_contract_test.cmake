if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/proxy/vless/outbound/vless_outbound.cpp"
    VLESS_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/trojan/outbound/trojan_outbound.cpp"
    TROJAN_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp"
    ANYTLS_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/vmess/outbound/vmess_outbound.cpp"
    VMESS_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/shadowsocks/outbound/ss_outbound.cpp"
    SHADOWSOCKS_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/freedom/freedom_outbound.cpp"
    FREEDOM_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/access_log_event.cpp"
    ACCESS_LOG_EVENT_SOURCE)

foreach(SOURCE IN ITEMS
        VLESS_OUTBOUND_SOURCE
        TROJAN_OUTBOUND_SOURCE
        ANYTLS_OUTBOUND_SOURCE)
    if(NOT "${${SOURCE}}" MATCHES
           "result[.]bytes_up [+]= prewritten_bytes" OR
       NOT "${${SOURCE}}" MATCHES
           "ctx[.]traffic[.]bytes_up = result[.]bytes_up")
        message(FATAL_ERROR
            "${SOURCE}: prewritten proxy payload must remain visible to access logging")
    endif()
endforeach()

if(ACCESS_LOG_EVENT_SOURCE MATCHES
       "event[.]remote_ip = AddressString[(][*]target[.]resolved_addr[)]")
    message(FATAL_ERROR
        "DNS candidates must not be reported as an established remote IP")
endif()

if(NOT ANYTLS_OUTBOUND_SOURCE MATCHES
       "if [(][!]prewrote_initial_payload && [!]initial_payload[.]empty[(][)][)]" OR
   NOT ANYTLS_OUTBOUND_SOURCE MATCHES
       "stats[.]AddBytesOut[(]prewritten_bytes[)]")
    message(FATAL_ERROR
        "AnyTLS open-packet payload must be sent once and counted as access traffic")
endif()

foreach(SOURCE IN ITEMS
        VMESS_OUTBOUND_SOURCE
        VLESS_OUTBOUND_SOURCE
        TROJAN_OUTBOUND_SOURCE
        SHADOWSOCKS_OUTBOUND_SOURCE
        ANYTLS_OUTBOUND_SOURCE
        FREEDOM_OUTBOUND_SOURCE)
    if(NOT "${${SOURCE}}" MATCHES "connected_local_addr")
        message(FATAL_ERROR
            "${SOURCE}: established outbound local IP must reach access-log metadata")
    endif()
endforeach()
