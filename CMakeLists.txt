cmake_minimum_required(VERSION 3.24)

# Manifest features must be selected before project() loads the vcpkg toolchain.
option(BUILD_TESTING "Configure unit and E2E tests (build with target cnode_tests)" OFF)
if(BUILD_TESTING)
    list(APPEND VCPKG_MANIFEST_FEATURES tests)
endif()
option(CNODE_IO_URING "Use Asio io_uring instead of epoll" OFF)
if(CNODE_IO_URING)
    list(APPEND VCPKG_MANIFEST_FEATURES io-uring)
endif()

project(cnode VERSION 1.0.0 LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CNODE_TARGET_IS_MUSL)
    message(FATAL_ERROR "cnode requires the musl toolchain; run mise run configure")
endif()
if(NOT VCPKG_TARGET_TRIPLET STREQUAL "x64-linux-musl")
    message(FATAL_ERROR "cnode requires the x64-linux-musl vcpkg triplet")
endif()

option(CNODE_ENABLE_LTO "Enable Release link-time optimization" ON)
option(CNODE_RELEASE_DEBUG_SYMBOLS "Emit Release debug information for split symbols" ON)
option(CNODE_RELEASE_FRAME_POINTERS "Keep Release frame pointers for profiling" ON)
option(CNODE_MEMORY_STATS "Enable runtime live/peak memory object counters" OFF)
set(CNODE_ASIO_RECYCLING_CACHE_SIZE 64 CACHE STRING "Asio per-thread small-block recycling cache size")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ${CNODE_ENABLE_LTO})

add_library(cnode_build_options INTERFACE)
target_compile_features(cnode_build_options INTERFACE cxx_std_20)
target_include_directories(cnode_build_options INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(cnode_build_options INTERFACE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-mismatched-new-delete
    "$<$<CXX_COMPILER_ID:GNU>:-Wno-stringop-overread;-Wno-free-nonheap-object>"
    "$<$<AND:$<CONFIG:Release>,$<BOOL:${CNODE_RELEASE_DEBUG_SYMBOLS}>>:-g>"
    "$<$<AND:$<CONFIG:Release>,$<BOOL:${CNODE_RELEASE_FRAME_POINTERS}>>:-fno-omit-frame-pointer>")
target_compile_definitions(cnode_build_options INTERFACE
    ASIO_STANDALONE ASIO_NO_DEPRECATED
    ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE=${CNODE_ASIO_RECYCLING_CACHE_SIZE}
    CNODE_USE_MIMALLOC
    $<$<BOOL:${CNODE_MEMORY_STATS}>:CNODE_MEMORY_STATS>)
find_package(Threads REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(tl-expected CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)
find_package(ngtcp2 CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)
find_package(ZLIB CONFIG REQUIRED COMPONENTS static)
find_package(concurrentqueue CONFIG REQUIRED)
find_package(blake3 CONFIG REQUIRED)
find_package(mimalloc CONFIG REQUIRED)

target_link_libraries(cnode_build_options INTERFACE
    asio::asio Threads::Threads tl::expected
    ngtcp2::ngtcp2_static ngtcp2::ngtcp2_crypto_boringssl_static
    nghttp3::nghttp3_static OpenSSL::SSL OpenSSL::Crypto
    ZLIB::ZLIBSTATIC concurrentqueue::concurrentqueue BLAKE3::blake3
    mimalloc-static-no-override)

# Upstream installs these headers in moodycamel/, while cnode uses their bare names.
get_target_property(cnode_queue_includes concurrentqueue::concurrentqueue INTERFACE_INCLUDE_DIRECTORIES)
foreach(directory IN LISTS cnode_queue_includes)
    target_include_directories(cnode_build_options SYSTEM INTERFACE "${directory}/moodycamel")
endforeach()

if(CNODE_IO_URING)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing)
    target_link_libraries(cnode_build_options INTERFACE PkgConfig::LIBURING)
    target_compile_definitions(cnode_build_options INTERFACE
        ASIO_HAS_IO_URING ASIO_DISABLE_EPOLL CNODE_IO_URING_ENABLED)
endif()
set(CNODE_CORE_SOURCES
    # Common (pure utilities)
    src/common/error.cpp

    # Infra (logging, config)
    src/infra/log.cpp
    src/infra/runtime_failure.cpp
    src/infra/json.cpp
    src/infra/config.cpp
    src/infra/inbound_field_rules.cpp
    src/infra/routing_ip_network.cpp
    src/infra/json_field.cpp
    src/infra/http2_initial_window.cpp
    src/infra/config_loader.cpp
    src/infra/config_semantics.cpp
    src/infra/config_validation.cpp
    src/infra/outbound_source_config.cpp

    # App - DNS
    src/app/dns/dns.cpp
    src/app/dns/cache.cpp

    # Geo
    src/geo/geodata.cpp

    # Transport - common stream interface
    src/transport/async_stream.cpp
    src/transport/internet/inbound_listen.cpp
    src/transport/internet/stream_settings.cpp
    src/transport/internet/outbound_bind.cpp

    # Transport - Internet
    src/transport/internet/datagram_socket.cpp
    src/transport/internet/tcp_stream.cpp
    src/transport/internet/timeout_scheduler.cpp
    src/transport/internet/tls_client_context.cpp
    src/transport/internet/tls_config.cpp
    src/transport/internet/tls_server_name.cpp
    src/transport/internet/tls_stream.cpp
    src/transport/internet/autosign_cert.cpp
    src/transport/internet/autosign_context.cpp
    src/transport/internet/reality_client_version.cpp
    src/transport/internet/reality_key.cpp
    src/transport/internet/reality_key_share.cpp
    src/transport/internet/reality_server_name.cpp
    src/transport/internet/reality_short_id.cpp
    src/transport/internet/reality_tls.cpp
    src/transport/internet/ws_stream.cpp
    src/transport/internet/http2_settings.cpp
    src/transport/internet/grpc_hunk.cpp
    src/transport/internet/http1_handshake.cpp
    src/transport/internet/xhttp_session.cpp
    src/transport/internet/http2_session.cpp
    src/transport/internet/transport_stack.cpp
    src/transport/internet/transport_dialer.cpp
    src/transport/internet/outbound_target_builder.cpp
    src/transport/internet/hysteria/hysteria_protocol.cpp
    src/transport/internet/hysteria/quic_memory.cpp
    src/transport/internet/hysteria/quic_stream.cpp
    src/transport/internet/hysteria/hysteria_ingress.cpp
    src/transport/internet/proxy_protocol.cpp

    # App (Application layer)
    src/app/dispatcher/default_dispatcher.cpp
    src/app/proxyman/inbound/factory.cpp
    src/app/proxyman/inbound/handler.cpp
    src/app/proxyman/inbound/handler_registry.cpp
    src/app/worker/tcp_listener.cpp
    src/app/worker/udp_ingress.cpp
    src/app/worker/udp_association_reclaimer.cpp
    src/app/proxyman/inbound/user_store.cpp
    src/app/proxyman/outbound/factory.cpp
    src/app/proxyman/outbound/handler.cpp
    src/app/worker.cpp
    src/app/session_group_executor.cpp
    src/app/session_capabilities.cpp
    src/service/controller/controller.cpp
    src/service/controller/traffic_journal.cpp
    src/common/awaitable_batch.cpp
    src/service/controller/node_transition.cpp
    src/service/controller/node_runtime.cpp
    src/service/controller/online_snapshot.cpp
    src/infra/panel_config.cpp
    src/infra/panel_node_ids.cpp
    src/service/controller/panel_inbound.cpp
    src/service/controller/control.cpp
    src/app/bootstrap_inbounds.cpp
    src/app/bootstrap_panels.cpp
    src/app/bootstrap_cli.cpp
    src/app/bootstrap_runtime.cpp
    src/app/bootstrap_monitor.cpp
    src/app/bootstrap_shutdown.cpp
    src/app/bootstrap_setup.cpp
    src/app/startup_inbounds.cpp
    src/app/prepared_inbound.cpp
    src/app/runtime_publication.cpp
    src/app/session_tracking.cpp
    src/proxy/mux/inbound/mux_inbound.cpp
    src/common/rule.cpp
    src/common/session.cpp
    src/common/sharded_user_stats.cpp
    src/app/stats.cpp
    src/app/bootstrap.cpp

    # Sniff
    src/sniff/sniffer.cpp
    src/sniff/tls_sniffer.cpp
    src/sniff/http_sniffer.cpp
    src/sniff/quic_sniffer.cpp

    # Common - Mux
    src/common/mux/mux_codec.cpp

    # Proxy - VMess
    src/proxy/vmess/vmess_crypto.cpp
    src/proxy/vmess/account.cpp
    src/proxy/vmess/validator.cpp
    src/proxy/vmess/vmess_cipher.cpp
    src/proxy/vmess/aead/authid.cpp
    src/proxy/vmess/aead/kdf.cpp
    src/proxy/vmess/aead/encrypt.cpp
    src/proxy/vmess/encoding/body.cpp
    src/proxy/vmess/encoding/client.cpp
    src/proxy/vmess/encoding/server.cpp
    src/proxy/vmess/inbound/vmess_inbound.cpp
    src/proxy/vmess/outbound/vmess_outbound.cpp

    # Proxy - VLESS
    src/proxy/vless/credentials.cpp
    src/proxy/vless/vless_codec.cpp
    src/proxy/vless/vless_encryption.cpp
    src/proxy/vless/vless_encryption_crypto.cpp
    src/proxy/vless/vless_encryption_handshake.cpp
    src/proxy/vless/vless_encryption_io.cpp
    src/proxy/vless/vless_encryption_record.cpp
    src/proxy/vless/vless_encryption_runtime.cpp
    src/proxy/vless/vless_ticket_service.cpp
    src/proxy/vless/vless_encryption_xor.cpp
    src/proxy/vless/udp_framing.cpp
    src/proxy/vless/vless_vision.cpp
    src/proxy/vless/inbound/vless_inbound.cpp
    src/proxy/vless/outbound/vless_outbound.cpp

    # Proxy - Trojan
    src/proxy/trojan/trojan_codec.cpp
    src/proxy/trojan/credentials.cpp
    src/proxy/trojan/udp_framing.cpp
    src/proxy/trojan/inbound/trojan_inbound.cpp
    src/proxy/trojan/outbound/trojan_outbound.cpp

    # Proxy - UDP over TCP
    src/proxy/uot/uot.cpp

    # Proxy - Hysteria
    src/proxy/hysteria/hysteria_inbound.cpp

    # Proxy - Shadowsocks
    src/proxy/shadowsocks/client.cpp
    src/proxy/shadowsocks/server.cpp
    src/proxy/shadowsocks/shadowsocks_protocol.cpp
    src/proxy/shadowsocks/ss_udp.cpp
    src/proxy/shadowsocks/inbound/ss_inbound.cpp
    src/proxy/shadowsocks/outbound/ss_outbound_uot.cpp
    src/proxy/shadowsocks/outbound/ss_outbound.cpp
    src/proxy/shadowsocks/outbound/ss_outbound_credentials.cpp

    # Proxy - AnyTLS
    src/proxy/anytls/anytls_codec.cpp
    src/proxy/anytls/padding.cpp
    src/proxy/anytls/credentials.cpp
    src/proxy/anytls/inbound/anytls_inbound.cpp
    src/proxy/anytls/outbound/anytls_outbound_settings.cpp
    src/proxy/anytls/outbound/anytls_outbound.cpp

    # Proxy - Freedom
    src/proxy/freedom/freedom_outbound.cpp

    # Proxy - Blackhole
    src/proxy/blackhole/blackhole_outbound.cpp

    # App - Router
    src/app/router/router.cpp

    # API / panel clients
    src/api/v2board/node_info_json.cpp
    src/api/v2board/online_report.cpp
    src/api/v2board/user_list_json.cpp
    src/api/v2board/v2board.cpp
)

# Full runtime consumers retain self-registering protocol translation units.
add_library(cnode_core STATIC ${CNODE_CORE_SOURCES})
target_link_libraries(cnode_core PUBLIC cnode_build_options)
target_precompile_headers(cnode_core PRIVATE src/pch.hpp)

if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(TIMESTAMP BUILD_ID "%Y%m%dT%H%M%SZ" UTC)
endif()
set_property(SOURCE src/app/bootstrap.cpp src/app/bootstrap_cli.cpp
    APPEND PROPERTY COMPILE_DEFINITIONS
    BUILD_ID="${BUILD_ID}"
    BUILD_CHANNEL="$<IF:$<CONFIG:Debug>,debug,release>")

add_executable(cnode src/main.cpp)
# Only the daemon overrides malloc/new. Tests retain their allocation-failure hooks;
# their explicit mi_* calls still use the same mimalloc API through build_options.
target_link_libraries(cnode PRIVATE
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core,mimalloc-static>")

add_executable(cnode_traffic_journal EXCLUDE_FROM_ALL tools/traffic_journal.cpp)
target_link_libraries(cnode_traffic_journal PRIVATE cnode_core)

if(NOT BUILD_TESTING)
    return()
endif()
enable_testing()

# Tests are opt-in and never part of the default production build.
find_package(GTest CONFIG REQUIRED)
include(GoogleTest)
add_custom_target(cnode_tests DEPENDS cnode)

# These recovery/lifetime fixtures observe buffer ownership and allocator failure.
# One consistently instrumented archive avoids both ODR violations and a complete
# production rebuild per fixture. Never link this archive together with cnode_core.
add_library(cnode_test_core STATIC EXCLUDE_FROM_ALL ${CNODE_CORE_SOURCES})
target_link_libraries(cnode_test_core PUBLIC cnode_build_options)
target_compile_definitions(cnode_test_core PUBLIC
    CNODE_TEST_ALLOCATOR_FAULT CNODE_TEST_BUFFER_STATS)
target_compile_options(cnode_test_core PRIVATE -UNDEBUG)

function(cnode_unit name)
    cmake_parse_arguments(TEST "" "LIBRARY;TIMEOUT" "SOURCES;INCLUDES" ${ARGN})
    if(NOT TEST_LIBRARY)
        set(TEST_LIBRARY cnode_core)
    endif()
    if(NOT TEST_TIMEOUT)
        set(TEST_TIMEOUT 90)
    endif()
    set(target cnode_${name}_test)
    add_executable(${target} EXCLUDE_FROM_ALL tests/${name}_test.cpp ${TEST_SOURCES})
    target_link_libraries(${target} PRIVATE ${TEST_LIBRARY} GTest::gtest_main)
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    foreach(directory IN LISTS TEST_INCLUDES)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${directory})
    endforeach()
    target_compile_options(${target} PRIVATE -UNDEBUG -Wno-mismatched-new-delete)
    add_dependencies(cnode_tests ${target})
    gtest_discover_tests(${target} DISCOVERY_MODE PRE_TEST
        TEST_PREFIX "${name}." PROPERTIES LABELS unit TIMEOUT ${TEST_TIMEOUT})
endfunction()

cnode_unit(anytls_codec_errors INCLUDES src/proxy/anytls)
cnode_unit(anytls_outbound_lifecycle LIBRARY cnode_test_core INCLUDES src/proxy/anytls/outbound)
cnode_unit(anytls_outbound_settings INCLUDES src/proxy/anytls/outbound)
cnode_unit(anytls_padding INCLUDES src/proxy/anytls)
cnode_unit(asio_operation_allocator)
cnode_unit(async_write_gate INCLUDES src/transport/internet)
cnode_unit(autosign_cert INCLUDES src/transport/internet)
cnode_unit(autosign_context INCLUDES src/transport/internet)
cnode_unit(awaitable_batch LIBRARY cnode_build_options SOURCES src/common/awaitable_batch.cpp INCLUDES src/common)
cnode_unit(awaitable_task_group LIBRARY cnode_build_options INCLUDES src/common)
cnode_unit(ban_tracking_contract)
cnode_unit(buffer_ownership)
cnode_unit(buffer_span_builder)
cnode_unit(cancellation_source)
cnode_unit(config_semantics INCLUDES src/infra)
cnode_unit(connection_timeouts)
cnode_unit(datagram_socket)
cnode_unit(dispatcher_cancellation)
cnode_unit(dns_cache)
cnode_unit(dns_datagram)
cnode_unit(dns_inflight)
cnode_unit(domain_name)
cnode_unit(geodata)
cnode_unit(grpc_hunk INCLUDES src/transport/internet)
cnode_unit(handler_registry)
cnode_unit(http2_flow_control)
cnode_unit(http2_initial_window INCLUDES src/infra src/transport/internet)
cnode_unit(http2_receive_credit)
cnode_unit(http2_server_errors)
cnode_unit(http_handshake_read_ahead LIBRARY cnode_test_core)
cnode_unit(http_path_match INCLUDES src/transport/internet)
cnode_unit(http_sniffer)
cnode_unit(hysteria_protocol INCLUDES src/transport/internet/hysteria)
cnode_unit(inbound_listen INCLUDES src/app)
cnode_unit(inbound_process_errors INCLUDES src/proxy/anytls)
cnode_unit(inbound_tls_policy INCLUDES src/service/controller)
cnode_unit(ip_address)
cnode_unit(json_field)
cnode_unit(json_object)
cnode_unit(log_format)
cnode_unit(monitor_loop)
cnode_unit(mux_codec INCLUDES src/proxy/mux/inbound)
cnode_unit(native_socket_handoff)
cnode_unit(node_transaction INCLUDES src/service/controller)
cnode_unit(node_transition INCLUDES src/service/controller)
cnode_unit(online_snapshot INCLUDES src/service/controller)
cnode_unit(outbound_bind)
cnode_unit(outbound_selection)
cnode_unit(panel_node_ids)
cnode_unit(panel_schedule INCLUDES src/service/controller)
cnode_unit(phase_deadline)
cnode_unit(process_resources)
cnode_unit(protocol_domain)
cnode_unit(protocol_registration LIBRARY "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core>" INCLUDES src/app/proxyman/outbound)
cnode_unit(proxy_protocol_literal)
cnode_unit(quic_directory INCLUDES src/transport/internet/hysteria)
cnode_unit(quic_sniffer)
cnode_unit(quic_stream LIBRARY cnode_test_core INCLUDES src/transport/internet/hysteria)
cnode_unit(reality_client_hello INCLUDES src/transport/internet)
cnode_unit(reality_client_version)
cnode_unit(reality_key_share INCLUDES src/transport/internet)
cnode_unit(reality_key)
cnode_unit(reality_server_name)
cnode_unit(reality_short_id)
cnode_unit(relay_initial_payload LIBRARY cnode_test_core)
cnode_unit(router)
cnode_unit(routing_ip_network)
cnode_unit(rule_lifecycle)
cnode_unit(session_access_log)
cnode_unit(session_group_executor)
cnode_unit(shadowsocks_stream_crypto LIBRARY cnode_build_options SOURCES src/proxy/shadowsocks/shadowsocks_protocol.cpp INCLUDES src/proxy/shadowsocks)
cnode_unit(shadowsocks_udp_datagram INCLUDES src/proxy/shadowsocks)
cnode_unit(sniff_config)
cnode_unit(ss_outbound_credentials INCLUDES src/proxy/shadowsocks)
cnode_unit(ss_outbound_uot INCLUDES src/proxy/shadowsocks/outbound)
cnode_unit(ss_udp_request)
cnode_unit(startup_inbounds INCLUDES src/app)
cnode_unit(stream_settings)
cnode_unit(substream_inbound_lifecycle LIBRARY cnode_test_core INCLUDES src/proxy/anytls/inbound src/proxy/mux/inbound)
cnode_unit(target_address)
cnode_unit(thread_memory_pool LIBRARY cnode_build_options)
cnode_unit(timeout_scheduler LIBRARY cnode_build_options SOURCES tests/timeout_scheduler_new.cpp src/transport/internet/timeout_scheduler.cpp src/app/session_group_executor.cpp src/infra/runtime_failure.cpp src/infra/log.cpp)
cnode_unit(tls_client_certificate INCLUDES src/transport/internet)
cnode_unit(tls_record_buffer LIBRARY cnode_test_core)
cnode_unit(tls_sniffer)
cnode_unit(token_bucket)
cnode_unit(traffic_journal)
cnode_unit(trojan_request INCLUDES src/proxy/trojan)
cnode_unit(trojan_udp_framing INCLUDES src/proxy/trojan)
cnode_unit(udp_association_reclaimer INCLUDES src/app)
cnode_unit(udp_native_lifecycle INCLUDES src/app src/proxy/shadowsocks)
cnode_unit(udp_request)
cnode_unit(udp_socket_owner LIBRARY cnode_test_core INCLUDES src/app)
cnode_unit(uot_ss2022 INCLUDES src/proxy/uot src/proxy/shadowsocks)
cnode_unit(user_store_batch)
cnode_unit(user_store_typed_payload)
cnode_unit(v2board_http_response INCLUDES src/api/v2board)
cnode_unit(v2board_node_info_json INCLUDES src/api/v2board)
cnode_unit(v2board_online_report INCLUDES src/api/v2board)
cnode_unit(v2board_request_task INCLUDES src/api/v2board)
cnode_unit(v2board_user_list_json INCLUDES src/api/v2board)
cnode_unit(vless_credentials INCLUDES src/proxy/vless)
cnode_unit(vless_encryption_io INCLUDES src/proxy/vless)
cnode_unit(vless_ticket_service INCLUDES src/proxy/vless)
cnode_unit(vless_ticket_store INCLUDES src/proxy/vless)
cnode_unit(vless_udp_framing INCLUDES src/proxy/vless)
cnode_unit(vless_vision INCLUDES src/proxy/vless)
cnode_unit(vmess_auth_snapshot INCLUDES src/proxy/vmess)
cnode_unit(vmess_cipher LIBRARY cnode_build_options SOURCES src/proxy/vmess/vmess_cipher.cpp src/proxy/vmess/vmess_crypto.cpp INCLUDES src/proxy/vmess)
cnode_unit(vmess_udp_datagram INCLUDES src/proxy/vmess)
cnode_unit(worker_connection_limit_runtime)
cnode_unit(worker_mailbox)
cnode_unit(worker_runtime_contract)
cnode_unit(worker_udp_retirement_runtime LIBRARY "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core>")
cnode_unit(xhttp_http1)
cnode_unit(xhttp_packet_queue INCLUDES src/transport/internet)
cnode_unit(xhttp_packet_session_key INCLUDES src/transport/internet)
cnode_unit(xhttp_session_lifecycle INCLUDES src/transport/internet)
cnode_unit(xhttp_upload_stream_slot INCLUDES src/transport/internet)

# Small isolated seams do not pull production objects compiled with other macros.
target_compile_definitions(cnode_thread_memory_pool_test PRIVATE
    CNODE_MEMORY_STATS CNODE_TEST_ALLOCATOR_FAULT)
target_compile_definitions(cnode_awaitable_batch_test PRIVATE
    ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING)
target_compile_definitions(cnode_awaitable_task_group_test PRIVATE
    ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING CNODE_MEMORY_STATS)
target_compile_options(cnode_awaitable_task_group_test PRIVATE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/tests/async_allocation_fault.hpp")
target_compile_options(cnode_timeout_scheduler_test PRIVATE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/tests/timeout_scheduler_allocation.hpp")
foreach(target IN ITEMS cnode_http_handshake_read_ahead_test cnode_tls_record_buffer_test)
    target_compile_definitions(${target} PRIVATE ACPP_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
endforeach()

# Keep EVP allocation/error injection visible to the linker, including Release.
foreach(target IN ITEMS cnode_vmess_cipher_test cnode_shadowsocks_stream_crypto_test)
    set_target_properties(${target} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF)
endforeach()
target_compile_definitions(cnode_vmess_cipher_test PRIVATE CNODE_TEST_CRYPTO_FAULT)
target_link_options(cnode_vmess_cipher_test PRIVATE
    -Wl,--wrap=EVP_MD_CTX_new -Wl,--wrap=EVP_AEAD_CTX_new -Wl,--wrap=EVP_DigestSqueeze)
target_compile_definitions(cnode_shadowsocks_stream_crypto_test PRIVATE
    CNODE_TEST_ALLOCATOR_FAULT CNODE_WRAP_MALLOC)
target_link_options(cnode_shadowsocks_stream_crypto_test PRIVATE
    -Wl,--wrap=malloc -Wl,--wrap=EVP_AEAD_CTX_new)

# Independent wire peers exercise the real cnode process, not its core archive.
find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
add_library(cnode_e2e_support STATIC EXCLUDE_FROM_ALL tests/e2e/support.cpp)
target_link_libraries(cnode_e2e_support PUBLIC
    cnode_build_options GTest::gtest nlohmann_json::nlohmann_json)
target_include_directories(cnode_e2e_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e)
target_compile_definitions(cnode_e2e_support PUBLIC
    CNODE_TEST_BINARY="$<TARGET_FILE:cnode>"
    CNODE_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(cnode_e2e_support PRIVATE -UNDEBUG)

function(cnode_e2e name source)
    set(target cnode_e2e_${name})
    add_executable(${target} EXCLUDE_FROM_ALL "${source}")
    target_link_libraries(${target} PRIVATE cnode_e2e_support GTest::gtest_main)
    target_compile_options(${target} PRIVATE -UNDEBUG)
    add_dependencies(${target} cnode)
    add_dependencies(cnode_tests ${target})
    set(timeout 180)
    if((name MATCHES "^http2_" AND NOT name STREQUAL "http2_deadline")
            OR name STREQUAL "reference_hysteria")
        set(timeout 600)
    elseif(name STREQUAL "config_panel_config")
        set(timeout 300)
    endif()
    gtest_discover_tests(${target} DISCOVERY_MODE PRE_TEST
        TEST_PREFIX "e2e.${name}." PROPERTIES LABELS e2e TIMEOUT ${timeout})
endfunction()

file(GLOB e2e_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/*.cpp")
list(FILTER e2e_sources EXCLUDE REGEX "/(support|reference_[^/]+|anytls_sessions_reference)\\.cpp$")
foreach(source IN LISTS e2e_sources)
    get_filename_component(name "${source}" NAME_WE)
    cnode_e2e("${name}" "${source}")
    if(name MATCHES "^udp_")
        target_link_libraries(cnode_e2e_${name} PRIVATE unofficial-sodium::sodium)
    elseif(name STREQUAL "config_panel_failure")
        target_sources(cnode_e2e_${name} PRIVATE src/infra/runtime_failure.cpp)
    elseif(name STREQUAL "config_panel_integrity")
        target_compile_definitions(cnode_e2e_${name} PRIVATE
            CNODE_TEST_JOURNAL_BINARY="$<TARGET_FILE:cnode_traffic_journal>")
        add_dependencies(cnode_e2e_${name} cnode_traffic_journal)
    endif()
endforeach()

# Reference binaries are explicit local inputs; configuration never downloads them.
set(CNODE_REFERENCE_GO "" CACHE FILEPATH "Go executable for reference provenance checks")
set(CNODE_REFERENCE_XRAY "" CACHE FILEPATH "Pinned Xray reference executable")
set(CNODE_REFERENCE_ANYTLS_CLIENT "" CACHE FILEPATH "Pinned AnyTLS reference client")
set(CNODE_REFERENCE_ANYTLS_SERVER "" CACHE FILEPATH "Pinned AnyTLS reference server")
set(CNODE_REFERENCE_HYSTERIA1 "" CACHE FILEPATH "Pinned Hysteria v1 reference executable")
set(CNODE_REFERENCE_HYSTERIA2 "" CACHE FILEPATH "Pinned Hysteria v2 reference executable")
foreach(group IN ITEMS xray anytls hysteria)
    if(group STREQUAL "xray")
        set(references CNODE_REFERENCE_XRAY)
    elseif(group STREQUAL "anytls")
        set(references CNODE_REFERENCE_ANYTLS_CLIENT CNODE_REFERENCE_ANYTLS_SERVER)
    else()
        set(references)
        foreach(reference IN ITEMS CNODE_REFERENCE_HYSTERIA1 CNODE_REFERENCE_HYSTERIA2)
            if(NOT "${${reference}}" STREQUAL "")
                list(APPEND references ${reference})
            endif()
        endforeach()
    endif()
    set(enabled OFF)
    foreach(reference IN LISTS references)
        if(NOT "${${reference}}" STREQUAL "")
            set(enabled ON)
        endif()
    endforeach()
    if(NOT enabled)
        continue()
    endif()
    list(APPEND references CNODE_REFERENCE_GO)
    foreach(reference IN LISTS references)
        if(NOT EXISTS "${${reference}}" OR IS_DIRECTORY "${${reference}}")
            message(FATAL_ERROR "${reference} must name an existing executable for ${group} E2E")
        endif()
    endforeach()
    cnode_e2e(reference_${group} "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/reference_${group}.cpp")
    foreach(reference IN LISTS references)
        target_compile_definitions(cnode_e2e_reference_${group} PRIVATE
            ${reference}="${${reference}}")
    endforeach()
    if(group STREQUAL "anytls")
        cnode_e2e(anytls_reference_padding_frame
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/anytls_padding_frame.cpp")
        target_compile_definitions(cnode_e2e_anytls_reference_padding_frame PRIVATE
            CNODE_REFERENCE_ANYTLS_CLIENT="${CNODE_REFERENCE_ANYTLS_CLIENT}"
            CNODE_REFERENCE_GO="${CNODE_REFERENCE_GO}")
        cnode_e2e(anytls_sessions_reference
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/anytls_sessions_reference.cpp")
        target_compile_definitions(cnode_e2e_anytls_sessions_reference PRIVATE
            CNODE_REFERENCE_GO="${CNODE_REFERENCE_GO}"
            CNODE_REFERENCE_ANYTLS_CLIENT="${CNODE_REFERENCE_ANYTLS_CLIENT}"
            CNODE_REFERENCE_ANYTLS_SERVER="${CNODE_REFERENCE_ANYTLS_SERVER}")
    endif()
endforeach()
