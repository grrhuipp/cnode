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
    "${SOURCE_DIR}/src/app/access_log_session.cpp"
    ACCESS_LOG_SESSION_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/relay_udp.cpp"
    UDP_RELAY_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/app/relay.hpp"
    RELAY_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/mux/inbound/mux_inbound.cpp"
    MUX_RELAY_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_handler.hpp"
    UDP_HANDLER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/proxyman/inbound/udp_worker.cpp"
    UDP_WORKER_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_worker.hpp"
    UDP_WORKER_HEADER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/worker.cpp"
    WORKER_SOURCE)

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

if(ACCESS_LOG_SESSION_SOURCE MATCHES
       "ctx_->inbound[.]user_id != 0" OR
   ACCESS_LOG_SESSION_SOURCE MATCHES
       "ctx_->outbound[.]target[.]IsValid[(][)]" OR
   NOT ACCESS_LOG_SESSION_SOURCE MATCHES
       "Reporter::Instance[(][)][.]Submit")
    message(FATAL_ERROR
        "centralized access logging must retain pre-authentication and targetless failures")
endif()

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

if(MUX_RELAY_SOURCE MATCHES
       "if [(][!]hdr[.]has_target [|][|] sub_sessions[.]contains[(]sid[)][)]")
    message(FATAL_ERROR
        "new Mux UDP requests without a target must enter dispatcher validation and access logging")
endif()

string(REGEX MATCHALL
       "ReportDispatchAdmissionFailure[(]sub_ptr->ctx[)]"
       MUX_ADMISSION_FAILURE_REPORTS
       "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_ADMISSION_FAILURE_REPORTS MUX_ADMISSION_FAILURE_REPORT_COUNT)
if(NOT MUX_RELAY_SOURCE MATCHES
       "access_log[.]Fail[(]ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT MUX_ADMISSION_FAILURE_REPORT_COUNT EQUAL 2)
    message(FATAL_ERROR
        "Mux TCP and UDP dispatch admission failures must reach access logging")
endif()

if(UDP_HANDLER_SOURCE MATCHES
       "optional<UdpDecodeResult>" OR
   NOT UDP_HANDLER_SOURCE MATCHES
       "expected<UdpDecodeResult, ErrorCode>" OR
   NOT UDP_WORKER_SOURCE MATCHES
       "access_log[.]Fail[(]decoded[.]error[(][)][)]")
    message(FATAL_ERROR
        "native UDP decode failures must retain their error and reach access logging")
endif()

if(NOT UDP_WORKER_HEADER_SOURCE MATCHES
       "enum class ReplyEnqueueResult")
    message(FATAL_ERROR
        "native UDP reply admission must distinguish rejection from queued work")
endif()
if(NOT UDP_WORKER_SOURCE MATCHES
       "return reply_sink[.]EnqueueUdpReply" OR
   NOT WORKER_SOURCE MATCHES
       "ReplyEnqueueResult::Rejected" OR
   NOT WORKER_SOURCE MATCHES
       "return false;")
    message(FATAL_ERROR
        "native UDP reply rejection must fail relay accounting and access logging")
endif()

if(NOT UDP_WORKER_SOURCE MATCHES
       "CloseWithError[(]ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT UDP_WORKER_SOURCE MATCHES
       "UDP client input queue full" OR
   NOT UDP_WORKER_SOURCE MATCHES
       "UDP client reply path closed")
    message(FATAL_ERROR
        "native UDP session termination must remain visible to access logging")
endif()

if(NOT UDP_WORKER_SOURCE MATCHES
       "catch [(]const std::bad_alloc&[)]" OR
   NOT UDP_WORKER_SOURCE MATCHES
       "access_log[.]Fail[(]ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT UDP_WORKER_SOURCE MATCHES
       "access_log[.]Fail[(]ErrorCode::INTERNAL[)]")
    message(FATAL_ERROR
        "native UDP dispatch admission and coroutine failures must reach access logging")
endif()

if(NOT MUX_RELAY_SOURCE MATCHES
       "Cancel[(]ErrorCode error = ErrorCode::CANCELLED[)]" OR
   NOT MUX_RELAY_SOURCE MATCHES
       "Cancel[(]ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT MUX_RELAY_SOURCE MATCHES
       "Mux TCP input cancelled" OR
   NOT MUX_RELAY_SOURCE MATCHES
       "Mux UDP input cancelled")
    message(FATAL_ERROR
        "Mux child input failures must remain visible to access logging")
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

if(NOT UDP_RELAY_SOURCE MATCHES
       "state[.]Fail[(]ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT UDP_RELAY_SOURCE MATCHES
       "result[.]error = state[.]terminal_error" OR
   NOT UDP_RELAY_SOURCE MATCHES
       "UDP Full Cone reply queue exhausted")
    message(FATAL_ERROR
        "Full Cone UDP reply rejection must terminate the relay and reach access logging")
endif()

if(NOT UDP_RELAY_SOURCE MATCHES
       "auto mark_close_side" OR
   NOT UDP_RELAY_SOURCE MATCHES
       "catch [(]const IoSystemError& e[)] [{][\r\n ]*mark_close_side[(]true[)]" OR
   NOT UDP_RELAY_SOURCE MATCHES
       "UDP reply write failed")
    message(FATAL_ERROR
        "UDP client read and reply-write failures must publish client close-side evidence")
endif()

if(NOT RELAY_SOURCE MATCHES
       "ObserveUdpRelayTarget" OR
   NOT RELAY_SOURCE MATCHES
       "ctx[.]content[.]multiple_targets = true" OR
   NOT UDP_RELAY_SOURCE MATCHES
       "ObserveUdpRelayTarget[(]ctx, read_mb[)]" OR
   NOT ACCESS_LOG_EVENT_SOURCE MATCHES
       "if [(][!]ctx[.]content[.]multiple_targets[)]")
    message(FATAL_ERROR
        "multi-target UDP sessions must not attribute aggregate traffic to the first target")
endif()

if(NOT RELAY_SOURCE MATCHES
       "struct RelayCloseState" OR
   NOT RELAY_SOURCE MATCHES
       "close_state[.]Mark[(]is_upload[)]" OR
   NOT RELAY_SOURCE MATCHES
       "result[.]close_side_known = close_state[.]known" OR
   NOT UDP_RELAY_SOURCE MATCHES
       "result[.]close_side_known = true")
    message(FATAL_ERROR
        "relay must capture the first terminal endpoint and publish its close-side evidence")
endif()

string(REGEX MATCHALL
       "result[.]client_closed_first = false"
       FIRST_PACKET_REMOTE_FAILURES
       "${RELAY_SOURCE}")
list(LENGTH FIRST_PACKET_REMOTE_FAILURES FIRST_PACKET_REMOTE_FAILURE_COUNT)
string(REGEX MATCHALL
       "result[.]close_side_known = true"
       FIRST_PACKET_KNOWN_FAILURES
       "${RELAY_SOURCE}")
list(LENGTH FIRST_PACKET_KNOWN_FAILURES FIRST_PACKET_KNOWN_FAILURE_COUNT)
if(NOT FIRST_PACKET_REMOTE_FAILURE_COUNT EQUAL 6 OR
   NOT FIRST_PACKET_KNOWN_FAILURE_COUNT EQUAL 6 OR
   NOT RELAY_SOURCE MATCHES
       "result[.]error = ErrorCode::RESOURCE_EXHAUSTED;[\r\n ]*result[.]error_msg = .first packet allocation failed.")
    message(FATAL_ERROR
        "first-packet target failures must report Remote while allocation failures stay local")
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

if(NOT ANYTLS_INBOUND_SOURCE MATCHES
       "report_predispatch_failure" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "access_log[.]Fail[(]error[)]" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "report_predispatch_failure[(]request[.]error[(][)][)]" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "report_predispatch_failure[(]ErrorCode::PROTOCOL_INVALID_ADDRESS[)]")
    message(FATAL_ERROR
        "AnyTLS UoT child failures before dispatcher entry must reach access logging")
endif()

if(NOT ANYTLS_INBOUND_SOURCE MATCHES
       "report_child_creation_failure" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "report_child_creation_failure[(][\r\n ]*sid,[\r\n ]*TargetAddress[{][}]" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "ErrorCode::PROTOCOL_INVALID_ADDRESS" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "uot_version [?] Network::UDP : Network::TCP")
    message(FATAL_ERROR
        "AnyTLS logical child creation failures must reach access logging")
endif()

if(NOT ANYTLS_INBOUND_SOURCE MATCHES
       "session::Context& ctx = sub->ctx" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "ReportStreamFailure[(]sid, ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT ANYTLS_INBOUND_SOURCE MATCHES
       "ReportStreamFailure[(]sid, ErrorCode::INTERNAL[)]")
    message(FATAL_ERROR
        "AnyTLS child context must exist before dispatch admission and report failures")
endif()

if(NOT ANYTLS_INBOUND_SOURCE MATCHES
       "AnyTLS substream cancelled" OR
   ANYTLS_INBOUND_SOURCE MATCHES
       "if [(]ec[)] [{][\r\n ]*co_return buf::MultiBuffer[{][}]" OR
   NOT ANYTLS_OUTBOUND_SOURCE MATCHES
       "payload[.]error[(][)] == ErrorCode::RESOURCE_EXHAUSTED" OR
   NOT ANYTLS_OUTBOUND_SOURCE MATCHES
       "io_error::no_buffer_space")
    message(FATAL_ERROR
        "AnyTLS child termination must remain visible to access logging")
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
