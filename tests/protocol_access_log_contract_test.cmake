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
    "${SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp"
    ANYTLS_INBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/vmess/inbound/vmess_inbound.cpp"
    VMESS_INBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/vless/inbound/vless_inbound.cpp"
    VLESS_INBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/trojan/inbound/trojan_inbound.cpp"
    TROJAN_INBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/shadowsocks/inbound/ss_inbound.cpp"
    SHADOWSOCKS_INBOUND_SOURCE)
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
file(READ
    "${SOURCE_DIR}/src/app/relay_udp.cpp"
    UDP_RELAY_SOURCE)
file(READ
    "${SOURCE_DIR}/src/common/mux/mux_relay.cpp"
    MUX_RELAY_SOURCE)

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

if(NOT MUX_RELAY_SOURCE MATCHES
       "bool CanPushTcp[(]size_t payload_bytes, size_t reply_count[)]" OR
   NOT MUX_RELAY_SOURCE MATCHES
       "Mux TCP reply queue full" OR
   NOT MUX_RELAY_SOURCE MATCHES
       "Mux UDP reply queue full")
    message(FATAL_ERROR
        "Mux child access traffic must fail instead of counting dropped replies")
endif()

string(FIND "${UDP_RELAY_SOURCE}"
       "auto send_result = co_await session.SendTo"
       UDP_SEND_POSITION)
string(FIND "${UDP_RELAY_SOURCE}"
       "ctx.traffic.bytes_up += datagram_info.payload_size"
       UDP_ACCOUNT_POSITION)
if(UDP_SEND_POSITION EQUAL -1 OR UDP_ACCOUNT_POSITION EQUAL -1 OR
   NOT UDP_SEND_POSITION LESS UDP_ACCOUNT_POSITION OR
   NOT UDP_RELAY_SOURCE MATCHES
       "result[.]error = send_result")
    message(FATAL_ERROR
        "UDP access traffic must be accounted only after a successful datagram send")
endif()

foreach(SOURCE IN ITEMS
        VMESS_INBOUND_SOURCE
        VLESS_INBOUND_SOURCE
        TROJAN_INBOUND_SOURCE
        SHADOWSOCKS_INBOUND_SOURCE
        ANYTLS_INBOUND_SOURCE)
    if(NOT "${${SOURCE}}" MATCHES "device_limit" OR
       NOT "${${SOURCE}}" MATCHES "ErrorCode::PERMISSION_DENIED")
        message(FATAL_ERROR
            "${SOURCE}: device-limit policy must be reported as a rejection")
    endif()
endforeach()

if(ANYTLS_INBOUND_SOURCE MATCHES "access_event_submitted" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "ctx[.]content[.]network = Network::MUX")
    message(FATAL_ERROR
        "AnyTLS must describe its control transport as MUX instead of controlling access logging")
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
