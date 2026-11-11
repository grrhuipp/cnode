cmake_minimum_required(VERSION 3.24)

# Manifest features must be selected before project() loads the vcpkg toolchain.
option(BUILD_TESTING "Configure unit and E2E tests (build with target cnode_tests)" OFF)
option(BUILD_BENCHMARKS "Configure opt-in benchmarks (requires BUILD_TESTING)" OFF)
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

option(CNODE_ENABLE_LTO "Enable Release link-time optimization" OFF)
option(CNODE_RELEASE_DEBUG_SYMBOLS "Emit Release debug information for split symbols" ON)
option(CNODE_RELEASE_FRAME_POINTERS "Keep Release frame pointers for profiling" ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ${CNODE_ENABLE_LTO})

add_library(cnode_build_options INTERFACE)
target_compile_features(cnode_build_options INTERFACE cxx_std_20)
target_include_directories(cnode_build_options INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_options(cnode_build_options INTERFACE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-mismatched-new-delete
    "$<$<AND:$<CONFIG:Release>,$<BOOL:${CNODE_RELEASE_DEBUG_SYMBOLS}>>:-g>"
    "$<$<AND:$<CONFIG:Release>,$<BOOL:${CNODE_RELEASE_FRAME_POINTERS}>>:-fno-omit-frame-pointer>")
# Allocation reuse belongs to mimalloc alone: Asio's per-thread handler and
# awaitable-frame caches would be a second cache layer over it.
target_compile_definitions(cnode_build_options INTERFACE
    ASIO_STANDALONE ASIO_NO_DEPRECATED
    ASIO_DISABLE_SMALL_BLOCK_RECYCLING ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING)
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

# Every binary, tests included, replaces malloc/new with mimalloc like the
# daemon; tests observe new/delete through cnode_allocation_hook instead.
target_link_libraries(cnode_build_options INTERFACE
    asio::asio Threads::Threads tl::expected
    ngtcp2::ngtcp2_static ngtcp2::ngtcp2_crypto_boringssl_static
    nghttp3::nghttp3_static OpenSSL::SSL OpenSSL::Crypto
    ZLIB::ZLIBSTATIC concurrentqueue::concurrentqueue BLAKE3::blake3
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,mimalloc-static>")

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
    # Infra (logging, config)
    src/infra/log.cpp
    src/infra/json.cpp
    src/infra/config.cpp

    # App - DNS
    src/app/dns/dns.cpp

    # Geo
    src/geo/geodata.cpp

    # Transport - common stream interface
    src/transport/async_stream.cpp
    src/transport/internet/stream_settings.cpp

    # Transport - Internet
    src/transport/internet/datagram_socket.cpp
    src/transport/internet/tcp_stream.cpp
    src/transport/internet/timeout_scheduler.cpp
    src/transport/internet/tls_stream.cpp
    src/transport/internet/ws_stream.cpp
    src/transport/internet/http1_handshake.cpp
    src/transport/internet/xhttp_session.cpp
    src/transport/internet/http2_session.cpp
    src/transport/internet/transport_stack.cpp
    src/transport/internet/transport_dialer.cpp
    src/transport/internet/hysteria/hysteria_ingress.cpp
    src/transport/internet/proxy_protocol.cpp

    # App (Application layer)
    src/app/dispatcher/default_dispatcher.cpp
    src/app/proxyman/inbound/handler.cpp
    src/app/worker/udp_ingress.cpp
    src/app/proxyman/inbound/user_store.cpp
    src/app/proxyman/outbound/handler.cpp
    src/app/worker.cpp
    src/app/session_group_executor.cpp
    src/service/controller/controller.cpp
    src/app/prepared_inbound.cpp
    src/common/rule.cpp
    src/common/session.cpp
    src/common/sharded_user_stats.cpp
    src/app/bootstrap.cpp

    # Sniff
    src/sniff/sniffer.cpp

    # Common - Mux
    src/common/mux/mux_codec.cpp

    # Proxy - VMess
    src/proxy/vmess/vmess_crypto.cpp
    src/proxy/vmess/encoding/body.cpp
    src/proxy/vmess/inbound/vmess_inbound.cpp
    src/proxy/vmess/outbound/vmess_outbound.cpp

    # Proxy - VLESS
    src/proxy/vless/vless_codec.cpp
    src/proxy/vless/vless_encryption.cpp
    src/proxy/vless/inbound/vless_inbound.cpp
    src/proxy/vless/outbound/vless_outbound.cpp

    # Proxy - Trojan
    src/proxy/trojan/trojan_codec.cpp
    src/proxy/trojan/inbound/trojan_inbound.cpp
    src/proxy/trojan/outbound/trojan_outbound.cpp

    # Proxy - UDP over TCP
    src/proxy/uot/uot.cpp

    # Proxy - Hysteria
    src/proxy/hysteria/hysteria_inbound.cpp

    # Proxy - Shadowsocks
    src/proxy/shadowsocks/shadowsocks_protocol.cpp
    src/proxy/shadowsocks/ss_udp.cpp
    src/proxy/shadowsocks/inbound/ss_inbound.cpp
    src/proxy/shadowsocks/outbound/ss_outbound.cpp

    # Proxy - AnyTLS
    src/proxy/anytls/anytls_codec.cpp
    src/proxy/anytls/inbound/anytls_inbound.cpp
    src/proxy/anytls/outbound/anytls_outbound.cpp

    # Proxy - Freedom
    src/proxy/freedom/freedom_outbound.cpp

    # Proxy - Blackhole
    src/proxy/blackhole/blackhole_outbound.cpp

    # App - Router
    src/app/router/router.cpp

    # API / panel clients
    src/api/v2board/v2board.cpp
)

# Full runtime consumers retain self-registering protocol translation units.
add_library(cnode_core STATIC ${CNODE_CORE_SOURCES})
target_link_libraries(cnode_core PUBLIC cnode_build_options)
target_precompile_headers(cnode_core PRIVATE src/pch.hpp)

if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(TIMESTAMP BUILD_ID "%Y%m%dT%H%M%SZ" UTC)
endif()
set_property(SOURCE src/app/bootstrap.cpp
    APPEND PROPERTY COMPILE_DEFINITIONS
    BUILD_ID="${BUILD_ID}"
    BUILD_CHANNEL="$<IF:$<CONFIG:Debug>,debug,release>")

add_executable(cnode src/main.cpp)
target_link_libraries(cnode PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core>")

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

# 单元测试、E2E 与基准共用的测试编译选项：Release 下断言同样生效，夹具从源码树读取。
add_library(cnode_test_options INTERFACE)
target_compile_options(cnode_test_options INTERFACE -UNDEBUG)
target_compile_definitions(cnode_test_options INTERFACE
    CNODE_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

# These recovery/lifetime fixtures observe buffer ownership and allocator failure.
# One consistently instrumented archive avoids both ODR violations and a complete
# production rebuild per fixture. Never link this archive together with cnode_core.
add_library(cnode_test_core STATIC EXCLUDE_FROM_ALL ${CNODE_CORE_SOURCES})
target_link_libraries(cnode_test_core PUBLIC cnode_build_options PRIVATE cnode_test_options)
target_compile_definitions(cnode_test_core PUBLIC
    CNODE_TEST_ALLOCATOR CNODE_TEST_BUFFER_STATS)
# 宏定义与 cnode_core 不同，不能 REUSE_FROM，单独生成一份 PCH。
target_precompile_headers(cnode_test_core PRIVATE src/pch.hpp)

# Fixtures that observe or fail global new/delete wrap it at link time and
# define allocation_hook::hooks; __real_* stays the overriding mimalloc.
add_library(cnode_allocation_hook INTERFACE)
target_sources(cnode_allocation_hook INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests/allocation_hook.cpp)
target_include_directories(cnode_allocation_hook INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_options(cnode_allocation_hook INTERFACE
    -Wl,--wrap=_Znwm -Wl,--wrap=_Znam
    -Wl,--wrap=_ZnwmRKSt9nothrow_t -Wl,--wrap=_ZnamRKSt9nothrow_t
    -Wl,--wrap=_ZdlPv -Wl,--wrap=_ZdaPv -Wl,--wrap=_ZdlPvm -Wl,--wrap=_ZdaPvm
    -Wl,--wrap=_ZdlPvRKSt9nothrow_t -Wl,--wrap=_ZdaPvRKSt9nothrow_t)

# tests/<name>_test.cpp → cnode_<name>_test。默认链接 cnode_core；LIBRARY 改链接目标，
# SOURCES 追加独立编译的源文件。
function(cnode_unit name)
    cmake_parse_arguments(TEST "" "LIBRARY" "SOURCES" ${ARGN})
    if(NOT TEST_LIBRARY)
        set(TEST_LIBRARY cnode_core)
    endif()
    set(target cnode_${name}_test)
    add_executable(${target} EXCLUDE_FROM_ALL tests/${name}_test.cpp ${TEST_SOURCES})
    target_link_libraries(${target} PRIVATE ${TEST_LIBRARY} cnode_test_options GTest::gtest_main)
    add_dependencies(cnode_tests ${target})
    gtest_discover_tests(${target} DISCOVERY_MODE PRE_TEST
        TEST_PREFIX "${name}." PROPERTIES LABELS unit TIMEOUT 90)
endfunction()

# 只有特殊链接的单元测试在此显式登记；其余 tests/*_test.cpp 由下方 glob 按默认方式登记。
foreach(name IN ITEMS
        allocator anytls_codec_errors anytls_outbound_lifecycle buffer_ownership
        buffer_span_builder dispatcher_cancellation dns_datagram http_handshake_read_ahead
        quic_stream relay_initial_payload substream_inbound_lifecycle tcp_read
        tls_record_buffer udp_socket_owner uot_ss2022 vless_udp_framing
        xhttp_upload_stream_slot)
    cnode_unit(${name} LIBRARY cnode_test_core)
endforeach()
foreach(name IN ITEMS protocol_registration runtime_sampling worker_udp_retirement_runtime)
    cnode_unit(${name} LIBRARY "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core>")
endforeach()
cnode_unit(awaitable_batch LIBRARY cnode_build_options)
cnode_unit(awaitable_task_group LIBRARY cnode_build_options)
cnode_unit(shadowsocks_stream_crypto LIBRARY cnode_build_options SOURCES src/proxy/shadowsocks/shadowsocks_protocol.cpp)
cnode_unit(timeout_scheduler LIBRARY cnode_build_options SOURCES src/transport/internet/timeout_scheduler.cpp src/app/session_group_executor.cpp src/infra/log.cpp)
cnode_unit(vmess_cipher LIBRARY cnode_build_options SOURCES src/proxy/vmess/vmess_crypto.cpp)

file(GLOB unit_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_test.cpp")
foreach(source IN LISTS unit_sources)
    get_filename_component(name "${source}" NAME_WE)
    string(REGEX REPLACE "_test$" "" name "${name}")
    if(NOT TARGET cnode_${name}_test)
        cnode_unit(${name})
    endif()
endforeach()

# Small isolated seams do not pull production objects compiled with other macros.
target_compile_options(cnode_awaitable_task_group_test PRIVATE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/tests/async_allocation_fault.hpp")
target_compile_options(cnode_timeout_scheduler_test PRIVATE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/tests/timeout_scheduler_allocation.hpp")

# Keep EVP allocation/error injection visible to the linker, including Release.
foreach(target IN ITEMS cnode_vmess_cipher_test cnode_shadowsocks_stream_crypto_test)
    set_target_properties(${target} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF)
endforeach()
target_compile_definitions(cnode_vmess_cipher_test PRIVATE CNODE_TEST_CRYPTO_FAULT)
target_link_options(cnode_vmess_cipher_test PRIVATE
    -Wl,--wrap=EVP_MD_CTX_new -Wl,--wrap=EVP_AEAD_CTX_new -Wl,--wrap=EVP_DigestSqueeze)
target_compile_definitions(cnode_shadowsocks_stream_crypto_test PRIVATE
    CNODE_TEST_ALLOCATOR CNODE_WRAP_MALLOC)
target_link_options(cnode_shadowsocks_stream_crypto_test PRIVATE
    -Wl,--wrap=malloc -Wl,--wrap=EVP_AEAD_CTX_new)
foreach(target IN ITEMS cnode_anytls_outbound_lifecycle_test cnode_anytls_padding_test
                        cnode_awaitable_batch_test cnode_awaitable_task_group_test
                        cnode_cancellation_source_test cnode_dns_inflight_test cnode_grpc_hunk_test
                        cnode_stream_settings_test cnode_timeout_scheduler_test
                        cnode_user_store_batch_test)
    target_link_libraries(${target} PRIVATE cnode_allocation_hook)
endforeach()

# Independent wire peers exercise the real cnode process, not its core archive.
find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
add_library(cnode_e2e_support STATIC EXCLUDE_FROM_ALL tests/e2e/support.cpp)
target_link_libraries(cnode_e2e_support PUBLIC
    cnode_build_options cnode_test_options GTest::gtest nlohmann_json::nlohmann_json)
target_include_directories(cnode_e2e_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e)
target_compile_definitions(cnode_e2e_support PUBLIC
    CNODE_TEST_BINARY="$<TARGET_FILE:cnode>")

function(cnode_e2e name source)
    set(target cnode_e2e_${name})
    add_executable(${target} EXCLUDE_FROM_ALL "${source}")
    target_link_libraries(${target} PRIVATE cnode_e2e_support GTest::gtest_main)
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

if(BUILD_BENCHMARKS)
    add_custom_target(cnode_benchmarks)
    # tests/<name>_benchmark.cpp → cnode_<name>_benchmark。E2E 基准取 tests/e2e/ 下的源文件，
    # 链接 cnode_e2e_support 并驱动真实 cnode 进程；COUNT_ALLOCATIONS 通过链接期 --wrap
    # 统计 operator new 与 mi_malloc_aligned 调用。
    function(cnode_benchmark name)
        cmake_parse_arguments(BENCHMARK "E2E;COUNT_ALLOCATIONS" "" "LIBRARY" ${ARGN})
        set(target cnode_${name}_benchmark)
        if(BENCHMARK_E2E)
            add_executable(${target} EXCLUDE_FROM_ALL tests/e2e/${name}_benchmark.cpp)
            target_link_libraries(${target} PRIVATE cnode_e2e_support)
            add_dependencies(${target} cnode)
        else()
            add_executable(${target} EXCLUDE_FROM_ALL tests/${name}_benchmark.cpp)
        endif()
        target_link_libraries(${target} PRIVATE ${BENCHMARK_LIBRARY} cnode_test_options GTest::gtest_main)
        if(BENCHMARK_COUNT_ALLOCATIONS)
            target_sources(${target} PRIVATE tests/benchmark_memory.cpp)
            target_link_options(${target} PRIVATE
                "-Wl,--wrap=_Znwm" "-Wl,--wrap=_Znam"
                "-Wl,--wrap=_ZnwmSt11align_val_t" "-Wl,--wrap=_ZnamSt11align_val_t"
                "-Wl,--wrap=mi_malloc_aligned")
        endif()
        add_dependencies(cnode_benchmarks ${target})
        gtest_discover_tests(${target} DISCOVERY_MODE PRE_TEST
            TEST_PREFIX "benchmark." PROPERTIES LABELS benchmark RUN_SERIAL TRUE TIMEOUT 180)
    endfunction()

    cnode_benchmark(allocator_append LIBRARY cnode_build_options)
    cnode_benchmark(tls_throughput E2E)
    cnode_benchmark(hysteria_throughput E2E)
    cnode_benchmark(tcp_receive LIBRARY cnode_core)
    foreach(name IN ITEMS executor tcp_send)
        cnode_benchmark(${name} LIBRARY "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core>")
    endforeach()
    foreach(name IN ITEMS udp_send runtime_sampling)
        cnode_benchmark(${name} COUNT_ALLOCATIONS LIBRARY "$<LINK_LIBRARY:WHOLE_ARCHIVE,cnode_core>")
    endforeach()
    foreach(name IN ITEMS shadowsocks_identity shadowsocks_udp_identity)
        cnode_benchmark(${name} COUNT_ALLOCATIONS LIBRARY cnode_core)
    endforeach()
endif()

file(GLOB e2e_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/*.cpp")
list(FILTER e2e_sources EXCLUDE REGEX "/(support|reference_[^/]+|anytls_sessions_reference|[^/]+_benchmark)\\.cpp$")
foreach(source IN LISTS e2e_sources)
    get_filename_component(name "${source}" NAME_WE)
    cnode_e2e("${name}" "${source}")
    if(name MATCHES "^udp_" OR name STREQUAL "quic_udp")
        target_link_libraries(cnode_e2e_${name} PRIVATE unofficial-sodium::sodium)
    elseif(name STREQUAL "config_panel_integrity")
        target_compile_definitions(cnode_e2e_${name} PRIVATE
            CNODE_TEST_JOURNAL_BINARY="$<TARGET_FILE:cnode_traffic_journal>")
        add_dependencies(cnode_e2e_${name} cnode_traffic_journal)
    elseif(name STREQUAL "config_panel_failure")
        target_link_libraries(cnode_e2e_${name} PRIVATE cnode_allocation_hook)
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
