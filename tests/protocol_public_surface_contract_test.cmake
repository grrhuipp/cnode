if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

foreach(interface_header IN ITEMS inbound.hpp outbound.hpp)
    if(NOT EXISTS "${SOURCE_DIR}/include/acppnode/proxy/${interface_header}")
        message(FATAL_ERROR
            "missing public proxy interface: ${interface_header}")
    endif()
endforeach()

set(PUBLIC_PROXY_ROOT "${SOURCE_DIR}/include/acppnode/proxy")
file(GLOB_RECURSE PUBLIC_PROXY_HEADERS
    LIST_DIRECTORIES false
    "${PUBLIC_PROXY_ROOT}/*.hpp")
foreach(header IN LISTS PUBLIC_PROXY_HEADERS)
    get_filename_component(header_dir "${header}" DIRECTORY)
    if(NOT header_dir STREQUAL PUBLIC_PROXY_ROOT)
        message(FATAL_ERROR
            "protocol-specific headers must remain private to src/proxy: ${header}")
    endif()
endforeach()

set(INBOUND_MANAGER
    "${SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp")
file(READ "${INBOUND_MANAGER}" INBOUND_MANAGER_SOURCE)
if(INBOUND_MANAGER_SOURCE MATCHES "#include[ \t]+\"acppnode/proxy/")
    message(FATAL_ERROR
        "inbound Manager must not include concrete protocol implementation headers")
endif()
if(INBOUND_MANAGER_SOURCE MATCHES "constants::protocol::")
    message(FATAL_ERROR
        "inbound Manager must not branch on concrete protocol tags")
endif()

set(ANYTLS_INBOUND
    "${SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp")
file(READ "${ANYTLS_INBOUND}" ANYTLS_INBOUND_SOURCE)
if(NOT ANYTLS_INBOUND_SOURCE MATCHES "co_await WaitForDispatches\\(\\)")
    message(FATAL_ERROR
        "AnyTLS demux must await every owned child dispatch before Run returns")
endif()
if(NOT ANYTLS_INBOUND_SOURCE MATCHES "active_dispatches_")
    message(FATAL_ERROR
        "AnyTLS demux must own explicit child dispatch lifetime state")
endif()
if(NOT ANYTLS_INBOUND_SOURCE MATCHES
       "transport::internet::AsyncWriteGate write_gate_" OR
   ANYTLS_INBOUND_SOURCE MATCHES "write_busy_|write_signal_")
    message(FATAL_ERROR
        "AnyTLS inbound writes must use the shared cancellation-broadcast gate")
endif()

set(ANYTLS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp")
file(READ "${ANYTLS_OUTBOUND}" ANYTLS_OUTBOUND_SOURCE)
if(NOT ANYTLS_OUTBOUND_SOURCE MATCHES "LogicalStreamLease")
    message(FATAL_ERROR
        "AnyTLS outbound logical streams must use exception-safe RAII ownership")
endif()
if(ANYTLS_OUTBOUND_SOURCE MATCHES "cleanup_logical_stream")
    message(FATAL_ERROR
        "AnyTLS outbound must not restore manual logical stream cleanup")
endif()
if(NOT ANYTLS_OUTBOUND_SOURCE MATCHES
       "transport::internet::AsyncWriteGate write_gate" OR
   NOT ANYTLS_OUTBOUND_SOURCE MATCHES
       "CloseAll[(]ok[.]error[(][)][)]" OR
   ANYTLS_OUTBOUND_SOURCE MATCHES
       "write_busy|write_signal|atomic_bool|closed[.](load|store)")
    message(FATAL_ERROR
        "AnyTLS outbound writes must broadcast terminal failures through the shared gate")
endif()

set(TRANSPORT_STACK
    "${SOURCE_DIR}/src/transport/internet/transport_stack.cpp")
file(READ "${TRANSPORT_STACK}" TRANSPORT_STACK_SOURCE)
file(READ
    "${SOURCE_DIR}/src/transport/internet/transport_dialer.cpp"
    TRANSPORT_DIALER_SOURCE)
if(TRANSPORT_DIALER_SOURCE MATCHES "next_seq_[+][+]" OR
   NOT TRANSPORT_DIALER_SOURCE MATCHES
       "if [(][!]build_result[)] \\{[^}]*ThrowXHttpPacketError[^}]*\\}[\r\n\t ]*[+][+]next_seq_;")
    message(FATAL_ERROR
        "XHTTP packet-up sequence must commit only after the server accepts the request")
endif()
file(READ
    "${SOURCE_DIR}/include/acppnode/transport/internet/ws_stream.hpp"
    WS_STREAM_SOURCE)
if(TRANSPORT_STACK_SOURCE MATCHES
       "void Cancel\\(\\) noexcept override \\{[\r\n\t ]*closed_ = true;" OR
   WS_STREAM_SOURCE MATCHES
       "void Cancel\\(\\) noexcept override \\{[\r\n\t ]*closed_ = true;")
    message(FATAL_ERROR
        "transport wrapper Cancel must not suppress the following Close operation")
endif()
file(READ
    "${SOURCE_DIR}/src/transport/internet/xhttp_packet_queue.hpp"
    XHTTP_PACKET_QUEUE_SOURCE)
file(READ
    "${SOURCE_DIR}/src/transport/internet/xhttp_upload_stream_slot.hpp"
    XHTTP_UPLOAD_SLOT_SOURCE)
if(NOT XHTTP_PACKET_QUEUE_SOURCE MATCHES
       "kMaxQueuedBytes = 4 [*] 1024 [*] 1024" OR
   NOT XHTTP_PACKET_QUEUE_SOURCE MATCHES
       "kMaxQueuedPackets = 1024" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "XHttpPacketQueue packet_queue_" OR
   TRANSPORT_STACK_SOURCE MATCHES
       "ThreadLocalMap<uint64_t, buf::MultiBuffer> pending_")
    message(FATAL_ERROR
        "XHTTP packet-up reordering must use the bounded Worker-local queue")
endif()
if(NOT XHTTP_UPLOAD_SLOT_SOURCE MATCHES
       "std::shared_ptr<Stream> Snapshot[(][)]" OR
   NOT XHTTP_UPLOAD_SLOT_SOURCE MATCHES
       "if [(][!]stream [|][|] current_[)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "stream_input_[.]Snapshot[(][)]" OR
   TRANSPORT_STACK_SOURCE MATCHES
       "std::unique_ptr<AsyncStream> stream_input_")
    message(FATAL_ERROR
        "XHTTP stream-up reads must retain one non-replaceable owner across await")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "XHttpPacketSessionKeyRef lookup_key\{&io_context, session_id\}" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "XHttpPacketSessionKey stored_key" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "[.]owner = &io_context")
    message(FATAL_ERROR
        "XHTTP packet session registry keys must include the owning io_context")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "kXHttpMaxPacketSessions = 1024" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "if [(]session->AcceptingInput[(][)][)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "if [(]sessions[.]size[(][)] >= kXHttpMaxPacketSessions[)]")
    message(FATAL_ERROR
        "XHTTP packet session registry must reject retired sessions and enforce a hard cap")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "void CancelPendingOperations[(][)] noexcept" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "ThrowIfReadCancelled[(][)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "session_->CancelPendingOperations[(][)]" OR
   TRANSPORT_STACK_SOURCE MATCHES
       "void Cancel[(][)] noexcept override \\{[\r\n\t ]*if [(]session_[)] \\{[\r\n\t ]*session_->Close[(][)]")
    message(FATAL_ERROR
        "XHTTP packet stream cancellation must abort pending reads without closing the session")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "ReadClientResponseHeaders[(]H2Frame frame[)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "field[.]name == \":status\"" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "HTTP/2 peer closed before response headers" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "HTTP/2 DATA arrived before response headers" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "HTTP/2 stream reset by peer" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "HTTP/2 connection closed by peer")
    message(FATAL_ERROR
        "HTTP/2 client streams must validate a successful response before accepting data or EOF")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "if [(]frame[.]length > kHttp2MaxFramePayload[)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "first_fragment->size[(][)] > kHttp2MaxHeaderBlockSize" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "kHttp2MaxHeaderBlockSize - header_block[.]size[(][)]" OR
   TRANSPORT_STACK_SOURCE MATCHES
       "frame[.]length > 16 [*] 1024 [*] 1024")
    message(FATAL_ERROR
        "HTTP/2 frame and accumulated header blocks must remain protocol bounded")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "kHttp2MaxConcurrentStreams = 256" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "[(]stream_id & 1u[)] == 0" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "stream_id <= last_remote_stream_id_" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "streams_[.]size[(][)] >= kHttp2MaxConcurrentStreams" OR
   TRANSPORT_STACK_SOURCE MATCHES
       "if [(]it != streams_[.]end[(][)][)] \\{[\r\n\t ]*return it->second;")
    message(FATAL_ERROR
        "HTTP/2 server streams must be unique, ordered, client-owned, and capacity bounded")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "kHpackMaxDynamicTableSize = 4096" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "if [(]size > kHpackMaxDynamicTableSize[)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "if [(][!]size [|][|] [!]ResizeDynamic[(][*]size[)][)]")
    message(FATAL_ERROR
        "HPACK peer table size updates must not exceed the local decoder limit")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES "StreamRemovalGuard")
    message(FATAL_ERROR
        "detached HTTP/2 server stream close must own exception-safe removal")
endif()
if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "transport::internet::AsyncWriteGate write_gate_" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "write_gate_[.]Cancel[(][)]" OR
   TRANSPORT_STACK_SOURCE MATCHES "write_busy_" OR
   TRANSPORT_STACK_SOURCE MATCHES "write_signal_")
    message(FATAL_ERROR
        "gRPC server writes must use the shared cancellation-broadcast gate")
endif()
string(FIND "${TRANSPORT_STACK_SOURCE}"
    "~StreamRemovalGuard() noexcept" STREAM_REMOVAL_GUARD_DESTRUCTOR)
if(STREAM_REMOVAL_GUARD_DESTRUCTOR EQUAL -1)
    message(FATAL_ERROR
        "HTTP/2 server stream removal must run while unwinding failed writes")
endif()

set(MUX_RELAY "${SOURCE_DIR}/src/common/mux/mux_relay.cpp")
file(READ "${MUX_RELAY}" MUX_RELAY_SOURCE)
if(NOT MUX_RELAY_SOURCE MATCHES
        "ThreadLocalUnorderedMap<uint16_t, MuxSubInfo> sub_sessions")
    message(FATAL_ERROR
        "Mux TCP and UDP substreams must share one session-id namespace")
endif()
if(MUX_RELAY_SOURCE MATCHES "udp_subs|tcp_subs")
    message(FATAL_ERROR
        "Mux must not restore per-network session-id namespaces")
endif()
if(NOT MUX_RELAY_SOURCE MATCHES "bool dispatch_done = false")
    message(FATAL_ERROR
        "Mux substream completion must notify cleanup independently from wire END")
endif()
if(NOT MUX_RELAY_SOURCE MATCHES
        "if [(]reply[.]dispatch_done[)][\r\n \t{]*sub_sessions[.]erase")
    message(FATAL_ERROR
        "Mux dispatch completion must remove the unified session entry")
endif()
if(MUX_RELAY_SOURCE MATCHES "packet_len > buf::Buffer::kSize")
    message(FATAL_ERROR
        "XUDP wire packet length must not be limited by one internal Buffer")
endif()
if(NOT MUX_RELAY_SOURCE MATCHES
        "const auto datagram = buf::InspectUdpDatagram[(]mb[)]" OR
   NOT MUX_RELAY_SOURCE MATCHES
        "mb[.]MoveTo[(]reply[.]payload, true[)]")
    message(FATAL_ERROR
        "Mux UDP replies must preserve one datagram across Buffer chunks")
endif()
set(VLESS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/vless/outbound/vless_outbound.cpp")
file(READ "${VLESS_OUTBOUND}" VLESS_OUTBOUND_SOURCE)
if(VLESS_OUTBOUND_SOURCE MATCHES "SameTargetAddress")
    message(FATAL_ERROR
        "VLESS must use the shared TargetAddress endpoint identity")
endif()
if(NOT VLESS_OUTBOUND_SOURCE MATCHES "EncodeNewHeaderTo")
    message(FATAL_ERROR
        "VLESS Mux must encode one complete MultiBuffer datagram length")
endif()
if(NOT VLESS_OUTBOUND_SOURCE MATCHES
        "target, payload_size[)]")
    message(FATAL_ERROR
        "VLESS Mux header must use the complete datagram payload size")
endif()
set(UOT_SOURCE "${SOURCE_DIR}/src/proxy/uot/uot.cpp")
file(READ "${UOT_SOURCE}" UOT_SOURCE_TEXT)
if(UOT_SOURCE_TEXT MATCHES "payload_size > buf::Buffer::kSize")
    message(FATAL_ERROR
        "UoT datagram length must not be limited by one Buffer")
endif()
if(NOT UOT_SOURCE_TEXT MATCHES
        "buf::InspectUdpDatagram[(]mb[)]" OR
   NOT UOT_SOURCE_TEXT MATCHES
        "WritePacket[(][*]target, payload[.]Span[(][)][)]")
    message(FATAL_ERROR
        "UoT must encode one complete MultiBuffer datagram per frame")
endif()
set(TROJAN_UDP_FRAMING
    "${SOURCE_DIR}/src/proxy/trojan/udp_framing.cpp")
set(TROJAN_INBOUND
    "${SOURCE_DIR}/src/proxy/trojan/inbound/trojan_inbound.cpp")
set(TROJAN_OUTBOUND
    "${SOURCE_DIR}/src/proxy/trojan/outbound/trojan_outbound.cpp")
file(READ "${TROJAN_UDP_FRAMING}" TROJAN_UDP_FRAMING_SOURCE)
file(READ "${TROJAN_INBOUND}" TROJAN_INBOUND_SOURCE)
file(READ "${TROJAN_OUTBOUND}" TROJAN_OUTBOUND_SOURCE)
foreach(TROJAN_ENDPOINT_SOURCE IN ITEMS
        TROJAN_INBOUND_SOURCE TROJAN_OUTBOUND_SOURCE)
    if(${TROJAN_ENDPOINT_SOURCE} MATCHES "class TrojanUdpFramer")
        message(FATAL_ERROR
            "Trojan endpoints must not duplicate UDP stream framing")
    endif()
    if(NOT ${TROJAN_ENDPOINT_SOURCE} MATCHES
            "trojan::WriteUdpDatagram")
        message(FATAL_ERROR
            "Trojan endpoints must use the shared datagram writer")
    endif()
    if(NOT ${TROJAN_ENDPOINT_SOURCE} MATCHES
            "co_return std::move[(]packet[.]payload[)]")
        message(FATAL_ERROR
            "Trojan UDP readers must return exactly one logical datagram")
    endif()
endforeach()
if(NOT TROJAN_UDP_FRAMING_SOURCE MATCHES
        "buf::InspectUdpDatagram[(]payload[)]" OR
   NOT TROJAN_UDP_FRAMING_SOURCE MATCHES
        "buf::AppendSpanToMultiBuffer")
    message(FATAL_ERROR
        "Trojan UDP framing must preserve complete MultiBuffer datagrams")
endif()
set(VLESS_UDP_FRAMING
    "${SOURCE_DIR}/src/proxy/vless/udp_framing.cpp")
set(VLESS_INBOUND
    "${SOURCE_DIR}/src/proxy/vless/inbound/vless_inbound.cpp")
set(VLESS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/vless/outbound/vless_outbound.cpp")
file(READ "${VLESS_UDP_FRAMING}" VLESS_UDP_FRAMING_SOURCE)
file(READ "${VLESS_INBOUND}" VLESS_INBOUND_SOURCE)
file(READ "${VLESS_OUTBOUND}" VLESS_OUTBOUND_SOURCE)
foreach(VLESS_ENDPOINT_SOURCE IN ITEMS
        VLESS_INBOUND_SOURCE VLESS_OUTBOUND_SOURCE)
    if(${VLESS_ENDPOINT_SOURCE} MATCHES "class VlessUdpFramer")
        message(FATAL_ERROR
            "VLESS endpoints must not duplicate UDP stream framing")
    endif()
    if(NOT ${VLESS_ENDPOINT_SOURCE} MATCHES
            "vless::WriteUdpDatagram")
        message(FATAL_ERROR
            "VLESS endpoints must use the shared datagram writer")
    endif()
    if(NOT ${VLESS_ENDPOINT_SOURCE} MATCHES
            "co_return std::move[(]packet[.]payload[)]")
        message(FATAL_ERROR
            "VLESS UDP readers must return exactly one logical datagram")
    endif()
endforeach()
if(NOT VLESS_UDP_FRAMING_SOURCE MATCHES
        "buf::InspectUdpDatagram[(]payload[)]" OR
   NOT VLESS_UDP_FRAMING_SOURCE MATCHES
        "buf::AppendSpanToMultiBuffer")
    message(FATAL_ERROR
        "VLESS UDP framing must preserve complete MultiBuffer datagrams")
endif()
set(VMESS_SERVER_ENCODING
    "${SOURCE_DIR}/src/proxy/vmess/encoding/server.cpp")
set(VMESS_CLIENT_ENCODING
    "${SOURCE_DIR}/src/proxy/vmess/encoding/client.cpp")
set(VMESS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/vmess/outbound/vmess_outbound.cpp")
file(READ "${VMESS_SERVER_ENCODING}" VMESS_SERVER_ENCODING_SOURCE)
file(READ "${VMESS_CLIENT_ENCODING}" VMESS_CLIENT_ENCODING_SOURCE)
file(READ "${VMESS_OUTBOUND}" VMESS_OUTBOUND_SOURCE)
if(NOT VMESS_SERVER_ENCODING_SOURCE MATCHES
        "state[.]packet_mode[)][ \t\r\n]*[{][ \t\r\n]*co_return co_await DecodeRequestBody")
    message(FATAL_ERROR
        "VMess UDP body reader must return exactly one authenticated chunk")
endif()
if(NOT VMESS_SERVER_ENCODING_SOURCE MATCHES
        "state[.]packet_mode = request[.]command == Command::UDP")
    message(FATAL_ERROR
        "VMess request body state must derive packet mode from the command")
endif()
string(REGEX MATCHALL
    "state[.]packet_mode = request[.]command == Command::UDP"
    VMESS_PACKET_MODE_INITIALIZERS "${VMESS_SERVER_ENCODING_SOURCE}")
list(LENGTH VMESS_PACKET_MODE_INITIALIZERS
    VMESS_PACKET_MODE_INITIALIZER_COUNT)
if(NOT VMESS_PACKET_MODE_INITIALIZER_COUNT EQUAL 2)
    message(FATAL_ERROR
        "VMess request reader and response writer must both derive packet mode")
endif()
if(NOT VMESS_OUTBOUND_SOURCE MATCHES
        "ValidateFixedUdpDatagram[(]mb, udp_target_[)]")
    message(FATAL_ERROR
        "VMess outbound must validate each complete UDP datagram atomically")
endif()
if(NOT VMESS_CLIENT_ENCODING_SOURCE MATCHES
        "request_body_state_[.]packet_mode = command_ == Command::UDP" OR
   NOT VMESS_CLIENT_ENCODING_SOURCE MATCHES
        "ContiguousBufferView packet[(]mb[)]" OR
   NOT VMESS_CLIENT_ENCODING_SOURCE MATCHES
        "EncodeRequestBodyChunk")
    message(FATAL_ERROR
        "VMess client UDP writer must encode one complete datagram per chunk")
endif()
if(NOT VMESS_SERVER_ENCODING_SOURCE MATCHES
        "state[.]packet_mode = request[.]command == Command::UDP" OR
   NOT VMESS_SERVER_ENCODING_SOURCE MATCHES
        "ContiguousBufferView packet[(]mb[)]" OR
   NOT VMESS_SERVER_ENCODING_SOURCE MATCHES
        "EncodeResponseBodyChunk[(]state, packet[.]Bytes[(][)], out_mb[)]")
    message(FATAL_ERROR
        "VMess server UDP writer must encode one complete datagram per chunk")
endif()
if(NOT VMESS_SERVER_ENCODING_SOURCE MATCHES
        "ValidateFixedUdpDatagram[(]mb, udp_target_[)]")
    message(FATAL_ERROR
        "VMess server response writer must validate each UDP datagram atomically")
endif()
set(SHADOWSOCKS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/shadowsocks/outbound/ss_outbound.cpp")
file(READ "${SHADOWSOCKS_OUTBOUND}" SHADOWSOCKS_OUTBOUND_SOURCE)
if(NOT SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "buf::InspectUdpDatagram[(]mb[)]" OR
   NOT SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "buf::ContiguousBufferView payload[(]mb[)]")
    message(FATAL_ERROR
        "Shadowsocks outbound must encode one complete MultiBuffer datagram")
endif()
if(SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "for [(]buf::Buffer[*] buffer : mb[)][ \t\r\n]*[{][\t\r\n ]*if .*EncodePacket")
    message(FATAL_ERROR
        "Shadowsocks outbound must not encode one UDP packet per Buffer")
endif()
if(NOT SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "Shadowsocks UDP scatter write requires a target")
    message(FATAL_ERROR
        "Shadowsocks UDP scatter writes must not be silently discarded")
endif()
set(SHADOWSOCKS_UDP_HEADER
    "${SOURCE_DIR}/src/proxy/shadowsocks/ss_udp.hpp")
set(SHADOWSOCKS_UDP_SOURCE
    "${SOURCE_DIR}/src/proxy/shadowsocks/ss_udp.cpp")
set(SHADOWSOCKS_INBOUND_SOURCE_PATH
    "${SOURCE_DIR}/src/proxy/shadowsocks/inbound/ss_inbound.cpp")
file(READ "${SHADOWSOCKS_UDP_HEADER}" SHADOWSOCKS_UDP_HEADER_SOURCE)
file(READ "${SHADOWSOCKS_UDP_SOURCE}" SHADOWSOCKS_UDP_SOURCE)
file(READ "${SHADOWSOCKS_INBOUND_SOURCE_PATH}" SHADOWSOCKS_INBOUND_SOURCE)
if(NOT SHADOWSOCKS_UDP_HEADER_SOURCE MATCHES
        "class Ss2022UdpReplayWindow" OR
   NOT SHADOWSOCKS_UDP_HEADER_SOURCE MATCHES
        "Ss2022UdpReplayCache&" OR
   NOT SHADOWSOCKS_UDP_SOURCE MATCHES
        "replay_cache[.]Accept[(]client_session_id, packet_id[)]" OR
   NOT SHADOWSOCKS_UDP_SOURCE MATCHES
        "receive_replay_cache[.]Accept[(]server_session_id, packet_id[)]")
    message(FATAL_ERROR
        "Shadowsocks 2022 UDP request and response paths must reject replayed packet IDs")
endif()
if(NOT SHADOWSOCKS_INBOUND_SOURCE MATCHES
        "session_owner[.]Assign[(]user[.]derived_key[.]span[(][)][)]")
    message(FATAL_ERROR
        "Shadowsocks UDP sessions must bind protocol session IDs to authenticated credentials")
endif()
if(NOT SHADOWSOCKS_INBOUND_SOURCE MATCHES
        "udp_replay_cache_ = std::move[(]previous_handler->udp_replay_cache_[)]")
    message(FATAL_ERROR
        "Shadowsocks handler replacement must preserve Worker-local UDP replay state")
endif()
if(SHADOWSOCKS_INBOUND_SOURCE MATCHES
        "Handler::EncodeUdpResponse" OR
   SHADOWSOCKS_INBOUND_SOURCE MATCHES
        "dynamic_cast<ShadowsocksUdpResponseContext")
    message(FATAL_ERROR
        "Shadowsocks UDP response encoding must belong to its captured session context")
endif()
set(UDP_RELAY "${SOURCE_DIR}/src/app/relay_udp.cpp")
file(READ "${UDP_RELAY}" UDP_RELAY_SOURCE)
if(NOT UDP_RELAY_SOURCE MATCHES
        "buf::InspectUdpDatagram[(]read_mb[)]")
    message(FATAL_ERROR
        "UDP relay must preserve one ReadMultiBuffer as one datagram")
endif()
set(UDP_SESSION "${SOURCE_DIR}/src/app/udp_session.cpp")
set(UDP_CALLBACK_ROUTER "${SOURCE_DIR}/src/app/udp_callback_router.cpp")
set(UDP_CALLBACK_ROUTER_HEADER "${SOURCE_DIR}/src/app/udp_callback_router.hpp")
set(UDP_SESSION_HEADER "${SOURCE_DIR}/include/acppnode/app/udp_session.hpp")
set(UDP_TYPES_HEADER "${SOURCE_DIR}/include/acppnode/app/udp_types.hpp")
file(READ "${UDP_SESSION}" UDP_SESSION_SOURCE)
file(READ "${UDP_CALLBACK_ROUTER}" UDP_CALLBACK_ROUTER_SOURCE)
file(READ "${UDP_CALLBACK_ROUTER_HEADER}" UDP_CALLBACK_ROUTER_HEADER_SOURCE)
file(READ "${UDP_SESSION_HEADER}" UDP_SESSION_HEADER_SOURCE)
file(READ "${UDP_TYPES_HEADER}" UDP_TYPES_HEADER_SOURCE)
if(UDP_SESSION_SOURCE MATCHES
        "async_receive_from[\r\n ()a-zA-Z0-9_,.>*&]*buf::Buffer::kSize")
    message(FATAL_ERROR
        "UDPSession receive capacity must not be limited to one Buffer")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES "socket[.]available")
    message(FATAL_ERROR
        "UDPSession must size large datagrams before receiving them")
endif()
string(REGEX MATCHALL "ResolveEndpoint[(]target[)]"
    UDP_RESOLVE_CALLS "${UDP_SESSION_SOURCE}")
list(LENGTH UDP_RESOLVE_CALLS UDP_RESOLVE_CALL_COUNT)
if(NOT UDP_RESOLVE_CALL_COUNT EQUAL 2)
    message(FATAL_ERROR
        "both UDPSession SendTo paths must share endpoint resolution")
endif()
string(REGEX MATCHALL "SendResolved[\r\n (]"
    UDP_SEND_CALLS "${UDP_SESSION_SOURCE}")
list(LENGTH UDP_SEND_CALLS UDP_SEND_CALL_COUNT)
if(UDP_SEND_CALL_COUNT LESS 3)
    message(FATAL_ERROR
        "UDPSession must centralize socket send, accounting and payload limits")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES
    "RunReceive[(]std::shared_ptr<Impl> self[)]")
    message(FATAL_ERROR
        "UDPSession receive loop must own Impl until cancellation completes")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES
        "receive_started = false" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "if [(]self->running[)]" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "[!]it->second->IsRunning[(][)]" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "const auto receive_error = session_handle->StartReceive[(][)]")
    message(FATAL_ERROR
        "UDPSession must reject duplicate receive loops and replace dead sessions")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES
        "it->second[.]use_count[(][)] != 1" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "it->second[.]use_count[(][)] == 1" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "std::allocate_shared<UDPSession>" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "it->second->CanRetire[(]impl_->session_timeout[)]" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "return std::unexpected[(]ErrorCode::NETWORK_IO_ERROR[)]")
    message(FATAL_ERROR
        "UDPSessionManager must retain sessions while Worker-local owning handles exist")
endif()
if(UDP_SESSION_HEADER_SOURCE MATCHES
        "const uint8_t[*] data,[\r\n ]+size_t len[\r\n ]*[)];")
    message(FATAL_ERROR
        "UDPSession sends must carry a registered callback identity")
endif()
set(FREEDOM_OUTBOUND_SOURCE_PATH
    "${SOURCE_DIR}/src/proxy/freedom/freedom_outbound.cpp")
file(READ "${FREEDOM_OUTBOUND_SOURCE_PATH}" FREEDOM_OUTBOUND_SOURCE)
if(NOT FREEDOM_OUTBOUND_SOURCE MATCHES
        "std::shared_ptr<UDPSession> session =" OR
   NOT SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "std::shared_ptr<UDPSession> session_" OR
   FREEDOM_OUTBOUND_SOURCE MATCHES
        "UDPSession[*] session =" OR
   SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "UDPSession& session_")
    message(FATAL_ERROR
        "UDP-capable outbounds must retain Worker-local owning session handles")
endif()
string(FIND "${UDP_SESSION_HEADER_SOURCE}" "private:" UDP_SESSION_PRIVATE_OFFSET)
string(FIND "${UDP_SESSION_HEADER_SOURCE}" "ErrorCode Start(" UDP_SESSION_START_OFFSET)
string(FIND "${UDP_SESSION_HEADER_SOURCE}" "ErrorCode StartReceive(" UDP_SESSION_RECEIVE_OFFSET)
string(FIND "${UDP_SESSION_HEADER_SOURCE}" "void Stop(" UDP_SESSION_STOP_OFFSET)
if(UDP_SESSION_PRIVATE_OFFSET LESS 0 OR
   UDP_SESSION_START_OFFSET LESS UDP_SESSION_PRIVATE_OFFSET OR
   UDP_SESSION_RECEIVE_OFFSET LESS UDP_SESSION_PRIVATE_OFFSET OR
   UDP_SESSION_STOP_OFFSET LESS UDP_SESSION_PRIVATE_OFFSET)
    message(FATAL_ERROR
        "UDPSession lifecycle must remain manager-owned private state")
endif()
if(UDP_SESSION_SOURCE MATCHES "retired_sessions")
    message(FATAL_ERROR
        "UDPSessionManager must not retain every removed session until shutdown")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES
    "UDPSessionManager::~UDPSessionManager[(][)] \\{[\r\n ]+StopAll[(][)];")
    message(FATAL_ERROR
        "UDPSessionManager destruction must cancel cleanup and live sessions")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES
        "StartCleanup[(][)] \\{[\r\n ]+if [(]impl_->running[)]" OR
   UDP_SESSION_HEADER_SOURCE MATCHES
        "TotalPackets(Sent|Received)" OR
   UDP_SESSION_HEADER_SOURCE MATCHES
        "(Packets|Bytes)(Sent|Received)[(][)] const")
    message(FATAL_ERROR
        "UDPSession cleanup must be idempotent and dead aggregate stats must stay removed")
endif()
if(UDP_SESSION_SOURCE MATCHES
       "registered_callbacks|target_to_callbacks" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "callbacks[.]RegisteredCount[(][)]" OR
   NOT UDP_CALLBACK_ROUTER_HEADER_SOURCE MATCHES
        "kMaxTargetsPerCallback = 256" OR
   NOT UDP_CALLBACK_ROUTER_HEADER_SOURCE MATCHES
        "kMaxTargetMappings = 4096" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "callbacks[.]BeginTargetSend[(]" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "mapping_lease[.]Commit[(][)]" OR
   UDP_SESSION_SOURCE MATCHES
        "RollbackTarget|CommitTarget" OR
   NOT UDP_CALLBACK_ROUTER_HEADER_SOURCE MATCHES
        "~MappingLease[(][)] noexcept" OR
   NOT UDP_CALLBACK_ROUTER_SOURCE MATCHES
        "MappingLease::Reset[(][)] noexcept" OR
   NOT UDP_CALLBACK_ROUTER_SOURCE MATCHES
        "owner_->RollbackTarget[(]token_[)]" OR
   NOT UDP_CALLBACK_ROUTER_SOURCE MATCHES
        "pending_removal" OR
   NOT UDP_CALLBACK_ROUTER_SOURCE MATCHES
        "DispatchScope" OR
   NOT UDP_CALLBACK_ROUTER_SOURCE MATCHES
        "target_it->second[.]generation != token[.]generation" OR
   NOT UDP_CALLBACK_ROUTER_SOURCE MATCHES
        "pending_sends")
    message(FATAL_ERROR
        "UDPSession callback routing must be bounded, reentrant-safe and generation-transactional")
endif()
if(NOT UDP_SESSION_SOURCE MATCHES
        "kMaxSessions = 4096" OR
   NOT UDP_SESSION_SOURCE MATCHES
        "[!]it->second->UsesBindAddress[(]bind_address[)]" OR
   NOT UDP_SESSION_HEADER_SOURCE MATCHES
        "std::expected<std::shared_ptr<UDPSession>, ErrorCode> AcquireSession" OR
   UDP_SESSION_HEADER_SOURCE MATCHES
        "GetOrCreateSession|GetSession[(]|RemoveSession[(]|SessionId[(]|expected<UDPSession[*]")
    message(FATAL_ERROR
        "UDPSessionManager acquisition must be bounded, bind-safe and expose exact errors")
endif()
if(NOT UDP_TYPES_HEADER_SOURCE MATCHES
        "return invoke_bool_[(]storage_, std::forward<Args>[(]args[)][.][.][.][)]")
    message(FATAL_ERROR
        "UDP callback rejection must propagate through inline type erasure")
endif()
set(UDP_WORKER_SOURCE_PATH
    "${SOURCE_DIR}/src/app/proxyman/inbound/udp_worker.cpp")
set(UDP_WORKER_HEADER_PATH
    "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_worker.hpp")
set(UDP_HANDLER_HEADER_PATH
    "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_handler.hpp")
file(READ "${UDP_WORKER_SOURCE_PATH}" UDP_WORKER_SOURCE)
file(READ "${UDP_WORKER_HEADER_PATH}" UDP_WORKER_HEADER_SOURCE)
file(READ "${UDP_HANDLER_HEADER_PATH}" UDP_HANDLER_HEADER_SOURCE)
set(LINK_HEADER_PATH "${SOURCE_DIR}/include/acppnode/transport/link.hpp")
file(READ "${LINK_HEADER_PATH}" LINK_HEADER_SOURCE)
set(MUX_RELAY_SOURCE_PATH "${SOURCE_DIR}/src/common/mux/mux_relay.cpp")
file(READ "${MUX_RELAY_SOURCE_PATH}" MUX_RELAY_SOURCE)
set(TROJAN_INBOUND_SOURCE_PATH
    "${SOURCE_DIR}/src/proxy/trojan/inbound/trojan_inbound.cpp")
file(READ "${TROJAN_INBOUND_SOURCE_PATH}" TROJAN_INBOUND_SOURCE)
if(NOT UDP_WORKER_SOURCE MATCHES
        "datagram[.]buffer_count == 1" OR
   NOT UDP_WORKER_SOURCE MATCHES
    "coalesced[.]reserve[(]datagram[.]payload_size[)]")
    message(FATAL_ERROR
        "UDP ClientSession must preserve one datagram across Buffer chunks")
endif()
if(NOT UDP_WORKER_SOURCE MATCHES
        "kMaxQueuedUdpDatagrams = 256" OR
   NOT UDP_WORKER_SOURCE MATCHES
        "kMaxQueuedUdpBytes = 512 [*] 1024" OR
   NOT UDP_WORKER_SOURCE MATCHES
        "WouldOverflowUdpQueue[(]" OR
   NOT UDP_WORKER_HEADER_SOURCE MATCHES
        "bool[\r\n ]+Push[(]")
    message(FATAL_ERROR
        "UDP input and reply queues must expose bounded backpressure")
endif()
if(NOT LINK_HEADER_SOURCE MATCHES
        "co_await WriteMultiBuffer[(]std::move[(]payload[)][)]" OR
   UDP_WORKER_SOURCE MATCHES
        "ClientSession::WriteBuffers" OR
   MUX_RELAY_SOURCE MATCHES
        "WriteBuffers[(]std::span<const net::const_buffer>[)][\r\n ]*override[\r\n ]*[{][\r\n ]*co_return" OR
   TROJAN_INBOUND_SOURCE MATCHES
        "WriteBuffers[(]std::span<const net::const_buffer>[)][\r\n ]*override[\r\n ]*[{][\r\n ]*co_return")
    message(FATAL_ERROR
        "packet writers must not silently discard raw scatter writes")
endif()
if(NOT UDP_WORKER_SOURCE MATCHES
        "session[.]link->UpdateReplyEndpoint[(]std::move[(]reply_endpoint[)][)]" OR
   NOT UDP_WORKER_SOURCE MATCHES
        "decoded->target,[\r\n ]+datagram[.]client_endpoint,[\r\n ]+decoded->session_owner,[\r\n ]+std::move[(]decoded->payload[)]" OR
   NOT UDP_WORKER_SOURCE MATCHES
        "const udp::endpoint& reply_endpoint")
    message(FATAL_ERROR
        "UDP ClientSession must route replies to the latest authenticated client endpoint")
endif()
if(NOT UDP_WORKER_SOURCE MATCHES
        "[!]session_it->second[.]link->Owns[(]session_owner[)]")
    message(FATAL_ERROR
        "UDP session key collisions must not cross authenticated owners")
endif()
if(NOT UDP_HANDLER_HEADER_SOURCE MATCHES "ScopeSessionKey" OR
   NOT UDP_WORKER_SOURCE MATCHES
        "decoded->session_owner[.]ScopeSessionKey[(]protocol_session_key[)]")
    message(FATAL_ERROR
        "UDP protocol session IDs must be scoped by authenticated owner identity")
endif()
if(UDP_HANDLER_HEADER_SOURCE MATCHES "EncodeUdpResponse" OR
   UDP_WORKER_SOURCE MATCHES "impl_->proxy->EncodeUdpResponse" OR
   NOT UDP_WORKER_SOURCE MATCHES "response_context->Encode[(]pkt[)]")
    message(FATAL_ERROR
        "live UDP sessions must encode replies through their captured response context")
endif()
if(NOT UDP_HANDLER_HEADER_SOURCE MATCHES "AdoptWorkerStateFrom" OR
   NOT UDP_WORKER_SOURCE MATCHES
        "proxy->AdoptWorkerStateFrom[(][*]impl_->proxy[)]" OR
   UDP_WORKER_SOURCE MATCHES
        "ReplaceHandler[(][^)]*[)][^{]*[{][^}]*CleanupAllClientSessions")
    message(FATAL_ERROR
        "UDP handler replacement must preserve live sessions and protocol Worker state")
endif()
set(WORKER_SOURCE_PATH "${SOURCE_DIR}/src/app/worker.cpp")
file(READ "${WORKER_SOURCE_PATH}" WORKER_SOURCE)
if(WORKER_SOURCE MATCHES
        "async_receive_from[\r\n ()a-zA-Z0-9_,.>*&]*kRecvBufSize")
    message(FATAL_ERROR
        "native UDP inbound receive must not be limited to one Buffer")
endif()
if(NOT WORKER_SOURCE MATCHES
        "detail::UdpReceiveBuffer receive_buffer")
    message(FATAL_ERROR
        "native UDP inbound must share the full-datagram receive path")
endif()
if(NOT UDP_RELAY_SOURCE MATCHES
        "session[.]SendTo[\r\n ()*,a-zA-Z0-9_.]*datagram[.]data[(][)]")
    message(FATAL_ERROR
        "UDP relay must send the coalesced datagram instead of each Buffer")
endif()
if(NOT UDP_RELAY_SOURCE MATCHES
        "kMaxUdpRelayQueuedReplies = 256" OR
   NOT UDP_RELAY_SOURCE MATCHES
        "kMaxUdpRelayQueuedBytes = 512 [*] 1024" OR
   NOT UDP_RELAY_SOURCE MATCHES
        "if [(]callback_id == 0[)]" OR
   NOT SHADOWSOCKS_OUTBOUND_SOURCE MATCHES
        "if [(][!]target_endpoint[.]Start[(][)][)]")
    message(FATAL_ERROR
        "UDP relay queues and callback registration must expose bounded failure")
endif()
if(NOT MUX_RELAY_SOURCE MATCHES "class SubLoopLease final")
    message(FATAL_ERROR
        "Mux detached sub-dispatch lifetime must be owned by its coroutine frame")
endif()
string(REGEX MATCHALL "SubLoopLease[{]reply_queue[}]"
    MUX_SUB_LOOP_LEASES "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_SUB_LOOP_LEASES MUX_SUB_LOOP_LEASE_COUNT)
if(NOT MUX_SUB_LOOP_LEASE_COUNT EQUAL 2)
    message(FATAL_ERROR
        "every TCP and UDP Mux sub-dispatch must receive an owned loop lease")
endif()
string(REGEX MATCHALL "void MarkDispatchDone[(][)] noexcept"
    MUX_NOEXCEPT_DISPATCH_COMPLETIONS "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_NOEXCEPT_DISPATCH_COMPLETIONS
    MUX_NOEXCEPT_DISPATCH_COMPLETION_COUNT)
if(NOT MUX_NOEXCEPT_DISPATCH_COMPLETION_COUNT EQUAL 2)
    message(FATAL_ERROR
        "TCP and UDP Mux dispatch completion must not strand loop ownership")
endif()
string(REGEX MATCHALL "QueueBytesWouldExceed"
    MUX_BOUNDED_QUEUE_CHECKS "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_BOUNDED_QUEUE_CHECKS MUX_BOUNDED_QUEUE_CHECK_COUNT)
if(MUX_BOUNDED_QUEUE_CHECK_COUNT LESS 7)
    message(FATAL_ERROR
        "every Mux input and reply queue must use overflow-safe byte limits")
endif()
if(NOT MUX_RELAY_SOURCE MATCHES "catch [(]const std::bad_alloc&[)]")
    message(FATAL_ERROR
        "Mux relay must enter owned async cleanup after allocation failure")
endif()

foreach(MUX_CONTROL_HEADER IN ITEMS
        "${SOURCE_DIR}/include/acppnode/app/mux_session_handler.hpp"
        "${SOURCE_DIR}/include/acppnode/common/mux/mux_relay.hpp")
    file(READ "${MUX_CONTROL_HEADER}" MUX_CONTROL_HEADER_SOURCE)
    if(MUX_CONTROL_HEADER_SOURCE MATCHES "AsyncStream[*]")
        message(FATAL_ERROR
            "Mux relay control stream must be a required non-null reference: ${MUX_CONTROL_HEADER}")
    endif()
endforeach()

set(DEFAULT_DISPATCHER
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp")
file(READ "${DEFAULT_DISPATCHER}" DEFAULT_DISPATCHER_SOURCE)
if(NOT DEFAULT_DISPATCHER_SOURCE MATCHES
        "if [(]!inbound_control[)]")
    message(FATAL_ERROR
        "Dispatcher must reject Mux links without a cancellable control stream")
endif()

set(VLESS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/vless/outbound/vless_outbound.cpp")
file(READ "${VLESS_OUTBOUND}" VLESS_OUTBOUND_SOURCE)
if(VLESS_OUTBOUND_SOURCE MATCHES
        "[+]\+pending_offset_[;]")
    message(FATAL_ERROR
        "VLESS outbound must not scan through invalid Mux frame bytes")
endif()
if(NOT VLESS_OUTBOUND_SOURCE MATCHES
        "frame[.]header[.]session_id != session_id_")
    message(FATAL_ERROR
        "VLESS Mux UDP responses must remain bound to their logical session")
endif()
if(VLESS_OUTBOUND_SOURCE MATCHES
        "VLESS mux request encode failed[^\n]*\n[^\n]*continue")
    message(FATAL_ERROR
        "VLESS Mux request encoding failures must propagate to relay")
endif()

set(MUX_CODEC "${SOURCE_DIR}/src/common/mux/mux_codec.cpp")
file(READ "${MUX_CODEC}" MUX_CODEC_SOURCE)
string(REGEX MATCHALL "DecodeFrameMetadata"
    MUX_METADATA_PARSER_REFERENCES "${MUX_CODEC_SOURCE}")
list(LENGTH MUX_METADATA_PARSER_REFERENCES
    MUX_METADATA_PARSER_REFERENCE_COUNT)
if(NOT MUX_METADATA_PARSER_REFERENCE_COUNT EQUAL 4)
    message(FATAL_ERROR
        "all three Mux byte layouts must share one metadata parser")
endif()
if(MUX_CODEC_SOURCE MATCHES "Remaining[(][)] >= 8")
    message(FATAL_ERROR
        "Mux GlobalID must be exactly eight metadata bytes")
endif()
