file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/link.hpp" link_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp" dispatcher_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/freedom/freedom_outbound.cpp" freedom_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/trojan/outbound/trojan_outbound.cpp" trojan_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/vmess/outbound/vmess_outbound.cpp" vmess_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/outbound/ss_outbound.cpp" shadowsocks_source)

if(NOT link_header MATCHES "AsyncStream\\*[ \t\r\n]+control[ \t\r\n]*=")
    message(FATAL_ERROR "transport::Link must carry optional inbound control for relay half-close handling")
endif()

if(NOT dispatcher_source MATCHES "transport::Link\\{inbound_reader,[ \t\r\n]*inbound_writer,[ \t\r\n]*inbound_control\\}")
    message(FATAL_ERROR "dispatcher must pass inbound control through transport::Link")
endif()

if(NOT freedom_source MATCHES "DoRelayLinkWithFirstPacket\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound_control,[ \t\r\n]*\\*stream")
    message(FATAL_ERROR "freedom outbound must use client-control relay overload for first payloads")
endif()

if(NOT freedom_source MATCHES "DoRelayLink\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound_control,[ \t\r\n]*\\*stream")
    message(FATAL_ERROR "freedom outbound must use client-control relay overload")
endif()

if(NOT trojan_source MATCHES "DoRelayLink\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound\\.control,[ \t\r\n]*\\*stream")
    message(FATAL_ERROR "trojan outbound must use client-control relay overload")
endif()

if(NOT vmess_source MATCHES "DoRelayLinkWithFirstPacket\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound\\.control,[ \t\r\n]*target_endpoint")
    message(FATAL_ERROR "vmess outbound must use client-control relay overload for first payloads")
endif()

if(NOT vmess_source MATCHES "DoRelayLink\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound\\.control,[ \t\r\n]*target_endpoint")
    message(FATAL_ERROR "vmess outbound must use client-control relay overload")
endif()

if(NOT shadowsocks_source MATCHES "DoRelayLinkWithFirstPacket\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound\\.control,[ \t\r\n]*target_endpoint")
    message(FATAL_ERROR "shadowsocks outbound must use client-control relay overload for first payloads")
endif()

if(NOT shadowsocks_source MATCHES "DoRelayLink\\([ \t\r\n]*io_context,[ \t\r\n]*\\*inbound\\.reader,[ \t\r\n]*\\*inbound\\.writer,[ \t\r\n]*\\*inbound\\.control,[ \t\r\n]*target_endpoint")
    message(FATAL_ERROR "shadowsocks outbound must use client-control relay overload")
endif()
