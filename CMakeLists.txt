cmake_minimum_required(VERSION 3.20)

# 抑制第三方依赖的 cmake_minimum_required 过旧警告
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

project(cnode VERSION 1.0.0 LANGUAGES C CXX)

include(FetchContent)

option(CNODE_HEAPTRACK_BUILD "Build a heaptrack-friendly glibc/system-allocator variant" OFF)
option(CNODE_AWSLC_NO_ASM "Disable AWS-LC assembly for local toolchains without nasm/perl" OFF)
option(CNODE_IO_URING "Use Asio io_uring backend on Linux" OFF)
option(CNODE_ENABLE_LTO "Enable Release link-time optimization" ON)
option(CNODE_RELEASE_DEBUG_SYMBOLS "Emit debug info for Release builds so CI can split .debug symbol files" ON)
option(CNODE_RELEASE_FRAME_POINTERS "Keep frame pointers in Release builds for perf/heaptrack symbolization" ON)
option(CNODE_BUILD_TESTS "Build cnode tests" OFF)
option(CNODE_TEST_SANITIZERS "Include ASan/UBSan regression targets in CTest" OFF)
# Keep Asio's existing per-io-thread, per-purpose cache large enough for
# completion batches. This does not replace global allocation or add a pool;
# buffers and application-owned objects still use the owning Worker's PMR.
set(CNODE_ASIO_RECYCLING_CACHE_SIZE 64 CACHE STRING "Asio small-block recycling cache size")
set(CNODE_LIBURING_TAG "liburing-2.14" CACHE STRING "axboe/liburing tag used for the io_uring backend")

if(CNODE_IO_URING AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "CNODE_IO_URING is only supported on Linux")
endif()

set(CNODE_COMPILER_MACHINE "")
set(CNODE_TARGET_IS_MUSL OFF)
if(UNIX AND NOT APPLE)
    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} -dumpmachine
        OUTPUT_VARIABLE CNODE_COMPILER_MACHINE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(CNODE_COMPILER_MACHINE MATCHES "musl" OR
       CMAKE_CXX_COMPILER MATCHES "musl")
        set(CNODE_TARGET_IS_MUSL ON)
    endif()
endif()

if(CNODE_HEAPTRACK_BUILD)
    if(CNODE_TARGET_IS_MUSL)
        message(FATAL_ERROR "CNODE_HEAPTRACK_BUILD requires a glibc toolchain, not musl")
    endif()
    message(STATUS "heaptrack variant: glibc/system allocator build")
endif()

# ============================================================================
# C++ 标准与编译选项
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
get_property(CNODE_IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

# ============================================================================
# LTO（链接时优化）— Release 模式启用
# ============================================================================
if(CNODE_ENABLE_LTO AND NOT CNODE_HEAPTRACK_BUILD)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()

if(CNODE_RELEASE_DEBUG_SYMBOLS)
    add_compile_options(
        $<$<AND:$<CONFIG:Release>,$<CXX_COMPILER_ID:MSVC>>:/Zi>
        $<$<AND:$<CONFIG:Release>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-g>
    )
endif()

if(CNODE_RELEASE_FRAME_POINTERS)
    add_compile_options(
        $<$<AND:$<CONFIG:Release>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-fno-omit-frame-pointer>
    )
endif()

if(CNODE_HEAPTRACK_BUILD)
    add_compile_options(
        $<$<CXX_COMPILER_ID:MSVC>:/Zi>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-g>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-fno-omit-frame-pointer>
    )
endif()

option(CNODE_MEMORY_STATS "Enable runtime live/peak memory object counters" OFF)

# ============================================================================
# 依赖（FetchContent）
# ============================================================================
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Do not update already-populated FetchContent deps")

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-32-0
)
FetchContent_MakeAvailable(asio)
include(cmake/patch_asio_tls.cmake)
cnode_patch_asio_tls("${asio_SOURCE_DIR}")

add_library(asio_standalone INTERFACE)
add_library(asio::asio ALIAS asio_standalone)
target_include_directories(asio_standalone INTERFACE
    ${asio_SOURCE_DIR}/asio/include
)
target_compile_definitions(asio_standalone INTERFACE
    ASIO_STANDALONE
    ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE=${CNODE_ASIO_RECYCLING_CACHE_SIZE}
)

if(CNODE_IO_URING)
    FetchContent_Declare(
        liburing
        GIT_REPOSITORY https://github.com/axboe/liburing.git
        GIT_TAG ${CNODE_LIBURING_TAG}
        GIT_SHALLOW TRUE
    )
    FetchContent_GetProperties(liburing)
    if(NOT liburing_POPULATED)
        FetchContent_Populate(liburing)
    endif()

    find_program(CNODE_MAKE_EXECUTABLE NAMES make gmake REQUIRED)
    set(CNODE_LIBURING_LIBRARY "${liburing_SOURCE_DIR}/src/liburing.a")
    set(CNODE_LIBURING_BUILD_STAMP "${liburing_BINARY_DIR}/cnode-liburing.stamp")
    add_custom_command(
        OUTPUT "${CNODE_LIBURING_LIBRARY}" "${CNODE_LIBURING_BUILD_STAMP}"
        COMMAND /bin/sh ./configure
            --use-libc
            "--cc=${CMAKE_C_COMPILER}"
            "--cxx=${CMAKE_CXX_COMPILER}"
        COMMAND "${CNODE_MAKE_EXECUTABLE}" -C "${liburing_SOURCE_DIR}" library ENABLE_SHARED=0
        COMMAND "${CMAKE_COMMAND}" -E touch "${CNODE_LIBURING_BUILD_STAMP}"
        WORKING_DIRECTORY "${liburing_SOURCE_DIR}"
        COMMENT "Building static liburing (${CNODE_LIBURING_TAG})"
        VERBATIM
    )
    add_custom_target(cnode_liburing_static DEPENDS "${CNODE_LIBURING_BUILD_STAMP}")

    target_include_directories(asio_standalone INTERFACE
        "${liburing_SOURCE_DIR}/src/include"
    )
    target_compile_definitions(asio_standalone INTERFACE
        ASIO_HAS_IO_URING
        ASIO_DISABLE_EPOLL
    )
endif()

set(BUILD_TESTING OFF CACHE BOOL "Disable third-party tests" FORCE)
set(BUILD_TOOL OFF CACHE BOOL "Disable AWS-LC bssl tool" FORCE)
set(DISABLE_GO ON CACHE BOOL "Disable AWS-LC Go helpers" FORCE)
unset(ENABLE_PRE_SONAME_BUILD CACHE)
unset(ENABLE_PRE_SONAME_BUILD)
if(CNODE_AWSLC_NO_ASM)
    set(OPENSSL_NO_ASM ON CACHE BOOL "Disable AWS-LC assembly" FORCE)
    set(DISABLE_PERL ON CACHE BOOL "Disable AWS-LC Perl assembly generation" FORCE)
else()
    set(DISABLE_PERL OFF CACHE BOOL "Enable AWS-LC Perl assembly generation" FORCE)
endif()

FetchContent_Declare(
    aws_lc
    GIT_REPOSITORY https://github.com/aws/aws-lc.git
    GIT_TAG v1.73.0
    PATCH_COMMAND
        ${CMAKE_COMMAND}
            -DAWS_LC_SOURCE_DIR=<SOURCE_DIR>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch_aws_lc_reality.cmake
)
FetchContent_MakeAvailable(aws_lc)
include(cmake/patch_aws_lc_reality.cmake)
cnode_patch_aws_lc_reality("${aws_lc_SOURCE_DIR}")
cnode_patch_aws_lc_tls_buffer("${aws_lc_SOURCE_DIR}")
cnode_patch_aws_lc_bio_idle("${aws_lc_SOURCE_DIR}")
message(STATUS "Using AWS-LC via FetchContent")

FetchContent_Declare(
    zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git
    GIT_TAG v1.3.1
    SOURCE_SUBDIR cnode-no-upstream-cmake
)
FetchContent_MakeAvailable(zlib)

FetchContent_Declare(
    concurrentqueue
    GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
    GIT_TAG v1.0.5
)
FetchContent_MakeAvailable(concurrentqueue)
message(STATUS "Using moodycamel ConcurrentQueue via FetchContent")

FetchContent_Declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG 1.8.5
    SOURCE_SUBDIR cnode-no-upstream-cmake
)
FetchContent_MakeAvailable(blake3)
add_library(cnode_blake3 STATIC
    ${blake3_SOURCE_DIR}/c/blake3.c
    ${blake3_SOURCE_DIR}/c/blake3_dispatch.c
    ${blake3_SOURCE_DIR}/c/blake3_portable.c
)
target_include_directories(cnode_blake3 PUBLIC ${blake3_SOURCE_DIR}/c)
include(cmake/blake3_simd.cmake)
message(STATUS "Using BLAKE3 via FetchContent")

add_library(cnode_zlib STATIC
    ${zlib_SOURCE_DIR}/adler32.c
    ${zlib_SOURCE_DIR}/compress.c
    ${zlib_SOURCE_DIR}/crc32.c
    ${zlib_SOURCE_DIR}/deflate.c
    ${zlib_SOURCE_DIR}/gzclose.c
    ${zlib_SOURCE_DIR}/gzlib.c
    ${zlib_SOURCE_DIR}/gzread.c
    ${zlib_SOURCE_DIR}/gzwrite.c
    ${zlib_SOURCE_DIR}/infback.c
    ${zlib_SOURCE_DIR}/inffast.c
    ${zlib_SOURCE_DIR}/inflate.c
    ${zlib_SOURCE_DIR}/inftrees.c
    ${zlib_SOURCE_DIR}/trees.c
    ${zlib_SOURCE_DIR}/uncompr.c
    ${zlib_SOURCE_DIR}/zutil.c
)
target_include_directories(cnode_zlib PUBLIC ${zlib_SOURCE_DIR})
if(UNIX)
    target_compile_definitions(cnode_zlib PRIVATE Z_HAVE_UNISTD_H)
endif()

find_package(Threads REQUIRED)
set(CNODE_ALLOCATOR_SUMMARY "system (global), Worker-local PMR pool")
message(STATUS "Allocator: ${CNODE_ALLOCATOR_SUMMARY}")

# ============================================================================
# 源文件收集
# ============================================================================
set(CNODE_SOURCES
    # Common (pure utilities)
    src/common/error.cpp
    src/common/serverstatus.cpp

    # Infra (logging, config)
    src/infra/log.cpp
    src/infra/json.cpp
    src/infra/config.cpp
    src/infra/routing_ip_network.cpp
    src/infra/json_bool.cpp
    src/infra/json_object.cpp
    src/infra/json_string.cpp
    src/infra/json_unsigned.cpp
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
    src/transport/internet/tcp_stream.cpp
    src/transport/internet/timeout_scheduler.cpp
    src/transport/internet/tls_client_context.cpp
    src/transport/internet/tls_server_name.cpp
    src/transport/internet/tls_stream.cpp
    src/transport/internet/autosign_cert.cpp
    src/transport/internet/reality_client_version.cpp
    src/transport/internet/reality_key.cpp
    src/transport/internet/reality_key_share.cpp
    src/transport/internet/reality_server_name.cpp
    src/transport/internet/reality_short_id.cpp
    src/transport/internet/reality_tls.cpp
    src/transport/internet/ws_stream.cpp
    src/transport/internet/http2_settings.cpp
    src/transport/internet/grpc_hunk.cpp
    src/transport/internet/tls_context_cache_key.cpp
    src/transport/internet/transport_stack.cpp
    src/transport/internet/transport_dialer.cpp
    src/transport/internet/outbound_target_builder.cpp
    src/transport/internet/proxy_protocol.cpp

    # App (Application layer)
    src/app/dispatcher/default_dispatcher.cpp
    src/app/proxyman/inbound/factory.cpp
    src/app/proxyman/inbound/handler.cpp
    src/app/proxyman/inbound/manager.cpp
    src/app/worker/tcp_listener.cpp
    src/app/worker/udp_ingress.cpp
    src/app/proxyman/inbound/user_store.cpp
    src/app/proxyman/outbound/factory.cpp
    src/app/proxyman/outbound/manager.cpp
    src/app/worker.cpp
    src/service/controller/controller.cpp
    src/common/awaitable_batch.cpp
    src/service/controller/node_transition.cpp
    src/service/controller/node_runtime.cpp
    src/service/controller/online_snapshot.cpp
    src/service/controller/config.cpp
    src/service/controller/panel_node_ids.cpp
    src/service/controller/inboundbuilder.cpp
    src/service/controller/outboundbuilder.cpp
    src/service/controller/userbuilder.cpp
    src/service/controller/control.cpp
    src/app/bootstrap_inbounds.cpp
    src/app/bootstrap_panels.cpp
    src/app/bootstrap_cli.cpp
    src/app/bootstrap_runtime.cpp
    src/app/bootstrap_monitor.cpp
    src/app/bootstrap_shutdown.cpp
    src/app/bootstrap_setup.cpp
    src/app/startup_inbounds.cpp
    src/app/udp_channel.cpp      # Worker-local UDP request endpoint
    src/app/session_tracking.cpp
    src/proxy/mux/inbound/mux_inbound.cpp
    src/common/rule.cpp
    src/common/session.cpp
    src/common/sharded_user_stats.cpp
    src/app/stats.cpp
    src/app/udp_callback_router.cpp
    src/app/udp_session.cpp
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
    src/proxy/vmess/encoding/client.cpp
    src/proxy/vmess/encoding/server.cpp
    src/proxy/vmess/inbound/vmess_inbound.cpp
    src/proxy/vmess/outbound/vmess_outbound.cpp

    # Proxy - VLESS
    src/proxy/vless/validator.cpp
    src/proxy/vless/credentials.cpp
    src/proxy/vless/vless_codec.cpp
    src/proxy/vless/vless_encryption.cpp
    src/proxy/vless/vless_encryption_crypto.cpp
    src/proxy/vless/vless_encryption_handshake.cpp
    src/proxy/vless/vless_encryption_io.cpp
    src/proxy/vless/vless_encryption_record.cpp
    src/proxy/vless/vless_encryption_runtime.cpp
    src/proxy/vless/vless_encryption_xor.cpp
    src/proxy/vless/udp_framing.cpp
    src/proxy/vless/vless_vision.cpp
    src/proxy/vless/inbound/vless_inbound.cpp
    src/proxy/vless/outbound/vless_outbound.cpp

    # Proxy - Trojan
    src/proxy/trojan/validator.cpp
    src/proxy/trojan/trojan_codec.cpp
    src/proxy/trojan/credentials.cpp
    src/proxy/trojan/udp_framing.cpp
    src/proxy/trojan/inbound/trojan_inbound.cpp
    src/proxy/trojan/outbound/trojan_outbound.cpp

    # Proxy - UDP over TCP
    src/proxy/uot/uot.cpp

    # Proxy - Shadowsocks
    src/proxy/shadowsocks/client.cpp
    src/proxy/shadowsocks/server.cpp
    src/proxy/shadowsocks/validator.cpp
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
    src/proxy/anytls/validator.cpp
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

    # Main
    src/main.cpp
)

# ============================================================================
# 可执行文件
# ============================================================================
add_executable(cnode ${CNODE_SOURCES})

target_include_directories(cnode PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${concurrentqueue_SOURCE_DIR}
)

target_link_libraries(cnode PRIVATE
    asio::asio
    Threads::Threads
    ssl
    crypto
    cnode_blake3
    cnode_zlib
)

if(CNODE_IO_URING)
    target_compile_definitions(cnode PRIVATE CNODE_IO_URING_ENABLED)
    add_dependencies(cnode cnode_liburing_static)
    target_link_libraries(cnode PRIVATE "${CNODE_LIBURING_LIBRARY}")
endif()

# 构建版本号：优先使用外部传入的 BUILD_ID，否则使用 UTC 时间戳
if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(TIMESTAMP BUILD_ID "%Y%m%dT%H%M%SZ" UTC)
endif()
if(NOT DEFINED GIT_COMMIT OR GIT_COMMIT STREQUAL "")
    execute_process(
        COMMAND git rev-parse --short=12 HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
endif()
if(GIT_COMMIT STREQUAL "")
    set(GIT_COMMIT "unknown")
endif()
if(CNODE_HEAPTRACK_BUILD)
    set(CNODE_BUILD_CHANNEL "heaptrack")
else()
    set(CNODE_BUILD_CHANNEL "$<IF:$<CONFIG:Debug>,debug,release>")
endif()
target_compile_definitions(cnode PRIVATE
    BUILD_ID="${BUILD_ID}"
    BUILD_CHANNEL="${CNODE_BUILD_CHANNEL}"
    CNODE_VERSION="${PROJECT_VERSION}"
    GIT_COMMIT="${GIT_COMMIT}"
)
message(STATUS "Build ID: ${BUILD_ID}")

if(CNODE_MEMORY_STATS)
    target_compile_definitions(cnode PRIVATE CNODE_MEMORY_STATS)
endif()

# 预编译头（PCH）- 加速 Asio/AWS-LC/标准库模板的编译
target_precompile_headers(cnode PRIVATE src/pch.hpp)

# 为我们自己的代码添加警告
target_compile_options(cnode PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4100 /wd4324 /EHsc /Zc:preprocessor /bigobj>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wno-unused-parameter -Wpedantic -Wno-mismatched-new-delete>
    $<$<CXX_COMPILER_ID:GNU>:-Wno-stringop-overread -Wno-free-nonheap-object>
)
target_link_options(cnode PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-Wno-stringop-overread -Wno-free-nonheap-object>
)


# 平台链接库
if(WIN32)
    target_link_libraries(cnode PRIVATE ws2_32 mswsock psapi crypt32 iphlpapi)
elseif(UNIX AND NOT APPLE)
    # glibc 需要显式链接 dl/rt，musl 已内置（find_library 自动区分）
    find_library(LIBDL dl)
    find_library(LIBRT rt)
    if(LIBDL)
        target_link_libraries(cnode PRIVATE ${LIBDL})
    endif()
    if(LIBRT)
        target_link_libraries(cnode PRIVATE ${LIBRT})
    endif()
endif()

if(CNODE_IS_MULTI_CONFIG)
    string(REPLACE ";" ", " CNODE_BUILD_TYPE_SUMMARY "${CMAKE_CONFIGURATION_TYPES}")
    set(CNODE_BUILD_TYPE_SUMMARY "multi-config (${CNODE_BUILD_TYPE_SUMMARY})")
else()
    set(CNODE_BUILD_TYPE_SUMMARY "${CMAKE_BUILD_TYPE}")
endif()

if(CNODE_HEAPTRACK_BUILD)
    set(CNODE_BUILD_CHANNEL_SUMMARY "heaptrack")
elseif(CNODE_IS_MULTI_CONFIG)
    set(CNODE_BUILD_CHANNEL_SUMMARY "per-config (Debug=debug, others=release)")
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CNODE_BUILD_CHANNEL_SUMMARY "debug")
else()
    set(CNODE_BUILD_CHANNEL_SUMMARY "release")
endif()

if(CNODE_HEAPTRACK_BUILD OR NOT CNODE_ENABLE_LTO)
    set(CNODE_LTO_SUMMARY "disabled")
elseif(CNODE_IS_MULTI_CONFIG)
    set(CNODE_LTO_SUMMARY "Release config")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CNODE_LTO_SUMMARY "enabled")
else()
    set(CNODE_LTO_SUMMARY "disabled")
endif()

if(CNODE_RELEASE_DEBUG_SYMBOLS)
    set(CNODE_RELEASE_DEBUG_SYMBOLS_SUMMARY "ON")
else()
    set(CNODE_RELEASE_DEBUG_SYMBOLS_SUMMARY "OFF")
endif()

if(CNODE_RELEASE_FRAME_POINTERS)
    set(CNODE_RELEASE_FRAME_POINTERS_SUMMARY "ON")
else()
    set(CNODE_RELEASE_FRAME_POINTERS_SUMMARY "OFF")
endif()

if(WIN32)
    set(CNODE_IO_BACKEND_SUMMARY "IOCP")
elseif(APPLE)
    set(CNODE_IO_BACKEND_SUMMARY "kqueue")
elseif(CNODE_IO_URING)
    set(CNODE_IO_BACKEND_SUMMARY "io_uring")
else()
    set(CNODE_IO_BACKEND_SUMMARY "epoll")
endif()

if(CNODE_BUILD_TESTS)
    enable_testing()

    add_executable(cnode_autosign_cert_test
        tests/autosign_cert_test.cpp
        src/transport/internet/autosign_cert.cpp
    )
    target_include_directories(cnode_autosign_cert_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_link_libraries(cnode_autosign_cert_test PRIVATE crypto)
    target_compile_options(cnode_autosign_cert_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_autosign_cert_test COMMAND cnode_autosign_cert_test)

    add_executable(cnode_tls_client_certificate_test
        tests/tls_client_certificate_test.cpp
        src/transport/internet/tls_client_context.cpp
        src/transport/internet/autosign_cert.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_tls_client_certificate_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_tls_client_certificate_test PRIVATE
        asio::asio
        Threads::Threads
        ssl
        crypto
        cnode_zlib
    )
    if(WIN32)
        target_link_libraries(cnode_tls_client_certificate_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_tls_client_certificate_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_tls_client_certificate_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4324 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_tls_client_certificate_test
        COMMAND cnode_tls_client_certificate_test)

    add_executable(cnode_tls_context_cache_key_test
        tests/tls_context_cache_key_test.cpp
        src/transport/internet/tls_context_cache_key.cpp
    )
    target_include_directories(cnode_tls_context_cache_key_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_link_libraries(cnode_tls_context_cache_key_test PRIVATE asio::asio)
    if(WIN32)
        target_compile_definitions(
            cnode_tls_context_cache_key_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_tls_context_cache_key_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_tls_context_cache_key_test
        COMMAND cnode_tls_context_cache_key_test)

    add_executable(cnode_tls_sniffer_test
        tests/tls_sniffer_test.cpp
        src/sniff/tls_sniffer.cpp
        src/transport/internet/tls_server_name.cpp
    )
    target_include_directories(cnode_tls_sniffer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_tls_sniffer_test PRIVATE asio::asio)
    if(WIN32)
        target_link_libraries(cnode_tls_sniffer_test PRIVATE ws2_32)
        target_compile_definitions(cnode_tls_sniffer_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_tls_sniffer_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_tls_sniffer_test
        COMMAND cnode_tls_sniffer_test)

    add_executable(cnode_http_sniffer_test
        tests/http_sniffer_test.cpp
        src/sniff/http_sniffer.cpp
    )
    target_include_directories(cnode_http_sniffer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_http_sniffer_test PRIVATE
        asio::asio
    )
    if(WIN32)
        target_link_libraries(cnode_http_sniffer_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_http_sniffer_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_http_sniffer_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_http_sniffer_test
        COMMAND cnode_http_sniffer_test)

    add_executable(cnode_quic_sniffer_test
        tests/quic_sniffer_test.cpp
        src/sniff/quic_sniffer.cpp
        src/sniff/tls_sniffer.cpp
        src/sniff/sniffer.cpp
        src/sniff/http_sniffer.cpp
        src/transport/internet/tls_server_name.cpp
    )
    target_include_directories(cnode_quic_sniffer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_quic_sniffer_test PRIVATE asio::asio crypto)
    if(WIN32)
        target_link_libraries(cnode_quic_sniffer_test PRIVATE ws2_32)
        target_compile_definitions(cnode_quic_sniffer_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_quic_sniffer_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_quic_sniffer_test
        COMMAND cnode_quic_sniffer_test)

    add_executable(cnode_sniff_config_test
        tests/sniff_config_test.cpp
    )
    target_include_directories(cnode_sniff_config_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_sniff_config_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_sniff_config_test
        COMMAND cnode_sniff_config_test)

    add_executable(cnode_domain_name_test
        tests/domain_name_test.cpp
    )
    target_include_directories(cnode_domain_name_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_domain_name_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_domain_name_test
        COMMAND cnode_domain_name_test)

    add_executable(cnode_ip_address_test tests/ip_address_test.cpp)
    target_include_directories(cnode_ip_address_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_ip_address_test PRIVATE asio::asio)
    if(WIN32)
        target_link_libraries(cnode_ip_address_test PRIVATE ws2_32)
        target_compile_definitions(cnode_ip_address_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_ip_address_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_ip_address_test COMMAND cnode_ip_address_test)

    add_executable(cnode_proxy_protocol_literal_test
        tests/proxy_protocol_literal_test.cpp
        src/transport/internet/proxy_protocol.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_proxy_protocol_literal_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR})
    target_link_libraries(cnode_proxy_protocol_literal_test PRIVATE
        asio::asio Threads::Threads crypto cnode_zlib)
    if(WIN32)
        target_link_libraries(cnode_proxy_protocol_literal_test PRIVATE ws2_32)
        target_compile_definitions(cnode_proxy_protocol_literal_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_proxy_protocol_literal_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_proxy_protocol_literal_test COMMAND cnode_proxy_protocol_literal_test)

    add_executable(cnode_target_address_test
        tests/target_address_test.cpp
    )
    target_include_directories(cnode_target_address_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_target_address_test PRIVATE
        asio::asio
    )
    if(WIN32)
        target_link_libraries(cnode_target_address_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_target_address_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_target_address_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_target_address_test
        COMMAND cnode_target_address_test)

    add_executable(cnode_reality_client_version_test
        tests/reality_client_version_test.cpp
        src/transport/internet/reality_client_version.cpp
    )
    target_include_directories(cnode_reality_client_version_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_reality_client_version_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_reality_client_version_test
        COMMAND cnode_reality_client_version_test)

    add_executable(cnode_reality_key_test
        tests/reality_key_test.cpp
        src/transport/internet/reality_key.cpp
    )
    target_include_directories(cnode_reality_key_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_reality_key_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_reality_key_test
        COMMAND cnode_reality_key_test)

    add_executable(cnode_reality_key_share_test
        tests/reality_key_share_test.cpp
        src/transport/internet/reality_key_share.cpp
    )
    target_include_directories(cnode_reality_key_share_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_compile_options(cnode_reality_key_share_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_reality_key_share_test
        COMMAND cnode_reality_key_share_test)

    add_executable(cnode_reality_server_name_test
        tests/reality_server_name_test.cpp
        src/transport/internet/reality_server_name.cpp
        src/transport/internet/tls_server_name.cpp
    )
    target_include_directories(cnode_reality_server_name_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_reality_server_name_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_reality_server_name_test
        COMMAND cnode_reality_server_name_test)

    add_executable(cnode_reality_short_id_test
        tests/reality_short_id_test.cpp
        src/transport/internet/reality_short_id.cpp
    )
    target_include_directories(cnode_reality_short_id_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_reality_short_id_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_reality_short_id_test
        COMMAND cnode_reality_short_id_test)

    add_executable(cnode_trojan_udp_framing_test
        tests/trojan_udp_framing_test.cpp
        src/infra/log.cpp
        src/proxy/trojan/trojan_codec.cpp
        src/proxy/trojan/udp_framing.cpp
    )
    add_executable(cnode_trojan_request_test
        tests/trojan_request_test.cpp
        src/infra/log.cpp
        src/proxy/trojan/trojan_codec.cpp
        src/proxy/trojan/credentials.cpp
    )
    target_include_directories(cnode_trojan_request_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/trojan
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_trojan_request_test PRIVATE
        asio::asio Threads::Threads crypto cnode_zlib)
    if(WIN32)
        target_link_libraries(cnode_trojan_request_test PRIVATE ws2_32)
        target_compile_definitions(cnode_trojan_request_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_trojan_request_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_trojan_request_test COMMAND cnode_trojan_request_test)

    add_executable(cnode_vless_credentials_test
        tests/vless_credentials_test.cpp
        src/proxy/vless/credentials.cpp
    )
    target_include_directories(cnode_vless_credentials_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/vless)
    target_link_libraries(cnode_vless_credentials_test PRIVATE crypto)
    target_compile_options(cnode_vless_credentials_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_vless_credentials_test COMMAND cnode_vless_credentials_test)

    target_include_directories(cnode_trojan_udp_framing_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/trojan
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_trojan_udp_framing_test PRIVATE
        asio::asio
        Threads::Threads
        crypto
        cnode_zlib
    )
    if(WIN32)
        target_link_libraries(cnode_trojan_udp_framing_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_trojan_udp_framing_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_trojan_udp_framing_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_trojan_udp_framing_test
        COMMAND cnode_trojan_udp_framing_test)

    add_executable(cnode_vless_udp_framing_test
        tests/vless_udp_framing_test.cpp
        src/infra/log.cpp
        src/proxy/vless/vless_codec.cpp
        src/proxy/vless/udp_framing.cpp
    )
    target_include_directories(cnode_vless_udp_framing_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/vless
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_vless_udp_framing_test PRIVATE
        asio::asio
        Threads::Threads
        cnode_zlib
    )
    if(WIN32)
        target_link_libraries(cnode_vless_udp_framing_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_vless_udp_framing_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_vless_udp_framing_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_vless_udp_framing_test
        COMMAND cnode_vless_udp_framing_test)

    add_executable(cnode_grpc_hunk_test
        tests/grpc_hunk_test.cpp
        src/transport/internet/grpc_hunk.cpp
    )
    target_include_directories(cnode_grpc_hunk_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_compile_options(cnode_grpc_hunk_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_grpc_hunk_test COMMAND cnode_grpc_hunk_test)

    add_executable(cnode_vmess_auth_snapshot_test
        tests/vmess_auth_snapshot_test.cpp
        src/proxy/vmess/validator.cpp
        src/proxy/vmess/aead/authid.cpp
        src/app/proxyman/inbound/user_store.cpp
        src/common/sharded_user_stats.cpp)
    target_include_directories(cnode_vmess_auth_snapshot_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/vmess)
    target_link_libraries(cnode_vmess_auth_snapshot_test PRIVATE asio::asio Threads::Threads cnode_zlib crypto)
    if(WIN32)
        target_link_libraries(cnode_vmess_auth_snapshot_test PRIVATE ws2_32)
        target_compile_definitions(cnode_vmess_auth_snapshot_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_vmess_auth_snapshot_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_vmess_auth_snapshot_test COMMAND cnode_vmess_auth_snapshot_test)

    add_executable(cnode_vmess_cipher_test
        tests/vmess_cipher_test.cpp
        src/proxy/vmess/vmess_cipher.cpp
    )
    target_include_directories(cnode_vmess_cipher_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/vmess
    )
    target_link_libraries(cnode_vmess_cipher_test PRIVATE asio::asio Threads::Threads crypto)
    if(WIN32)
        target_link_libraries(cnode_vmess_cipher_test PRIVATE ws2_32)
        target_compile_definitions(cnode_vmess_cipher_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_vmess_cipher_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_vmess_cipher_test COMMAND cnode_vmess_cipher_test)

    add_executable(cnode_vmess_udp_datagram_test
        tests/vmess_udp_datagram_test.cpp
    )
    target_include_directories(cnode_vmess_udp_datagram_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/vmess
    )
    target_link_libraries(cnode_vmess_udp_datagram_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_vmess_udp_datagram_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_vmess_udp_datagram_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_vmess_udp_datagram_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_vmess_udp_datagram_test
        COMMAND cnode_vmess_udp_datagram_test)

    add_executable(cnode_shadowsocks_udp_datagram_test
        tests/shadowsocks_udp_datagram_test.cpp
        src/proxy/shadowsocks/shadowsocks_protocol.cpp
        src/proxy/shadowsocks/ss_udp.cpp
    )
    target_include_directories(cnode_shadowsocks_udp_datagram_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/shadowsocks
        ${blake3_SOURCE_DIR}/c
    )
    target_link_libraries(cnode_shadowsocks_udp_datagram_test PRIVATE
        asio::asio
        Threads::Threads
        crypto
        cnode_blake3
    )
    if(WIN32)
        target_link_libraries(cnode_shadowsocks_udp_datagram_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_shadowsocks_udp_datagram_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_shadowsocks_udp_datagram_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_shadowsocks_udp_datagram_test
        COMMAND cnode_shadowsocks_udp_datagram_test)

    add_executable(cnode_uot_ss2022_test
        tests/uot_ss2022_test.cpp
        src/proxy/uot/uot.cpp
        src/proxy/shadowsocks/shadowsocks_protocol.cpp
    )
    target_include_directories(cnode_uot_ss2022_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/uot
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/shadowsocks
        ${blake3_SOURCE_DIR}/c
    )
    target_link_libraries(cnode_uot_ss2022_test PRIVATE
        asio::asio
        Threads::Threads
        crypto
        cnode_blake3
    )
    if(WIN32)
        target_link_libraries(cnode_uot_ss2022_test PRIVATE ws2_32)
    endif()
    target_compile_options(cnode_uot_ss2022_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_uot_ss2022_test COMMAND cnode_uot_ss2022_test)

    add_executable(cnode_ss_outbound_credentials_test
        tests/ss_outbound_credentials_test.cpp
        src/proxy/shadowsocks/outbound/ss_outbound_credentials.cpp
        src/proxy/shadowsocks/shadowsocks_protocol.cpp
    )
    target_include_directories(cnode_ss_outbound_credentials_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/shadowsocks
        ${blake3_SOURCE_DIR}/c
    )
    target_link_libraries(cnode_ss_outbound_credentials_test PRIVATE
        asio::asio Threads::Threads crypto cnode_blake3)
    if(WIN32)
        target_link_libraries(cnode_ss_outbound_credentials_test PRIVATE ws2_32)
    endif()
    target_compile_options(cnode_ss_outbound_credentials_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_ss_outbound_credentials_test COMMAND cnode_ss_outbound_credentials_test)

    add_executable(cnode_mux_codec_test
        tests/mux_codec_test.cpp
        src/common/mux/mux_codec.cpp
    )
    target_include_directories(cnode_mux_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/mux/inbound
    )
    target_link_libraries(cnode_mux_codec_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_mux_codec_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_mux_codec_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_mux_codec_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_mux_codec_test COMMAND cnode_mux_codec_test)

    add_executable(cnode_shadowsocks_stream_crypto_test
        tests/shadowsocks_stream_crypto_test.cpp
        src/proxy/shadowsocks/shadowsocks_protocol.cpp
    )
    target_include_directories(cnode_shadowsocks_stream_crypto_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/shadowsocks
        ${blake3_SOURCE_DIR}/c
    )
    target_link_libraries(cnode_shadowsocks_stream_crypto_test PRIVATE
        asio::asio
        Threads::Threads
        crypto
        cnode_blake3
    )
    if(WIN32)
        target_link_libraries(cnode_shadowsocks_stream_crypto_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_shadowsocks_stream_crypto_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_shadowsocks_stream_crypto_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_shadowsocks_stream_crypto_test
        COMMAND cnode_shadowsocks_stream_crypto_test)

    add_executable(cnode_v2board_http_response_test
        tests/v2board_http_response_test.cpp
    )
    target_include_directories(cnode_v2board_http_response_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api/v2board
    )
    target_link_libraries(cnode_v2board_http_response_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_v2board_http_response_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_v2board_http_response_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_v2board_http_response_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_v2board_http_response_test
        COMMAND cnode_v2board_http_response_test)

    add_executable(cnode_v2board_request_task_test tests/v2board_request_task_test.cpp)
    target_include_directories(cnode_v2board_request_task_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api/v2board)
    target_link_libraries(cnode_v2board_request_task_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_link_libraries(cnode_v2board_request_task_test PRIVATE ws2_32)
        target_compile_definitions(cnode_v2board_request_task_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_v2board_request_task_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_v2board_request_task_test COMMAND cnode_v2board_request_task_test)
    set_tests_properties(cnode_v2board_request_task_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_online_snapshot_test
        tests/online_snapshot_test.cpp
        src/service/controller/online_snapshot.cpp
    )
    target_include_directories(cnode_online_snapshot_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/service/controller
    )
    target_link_libraries(cnode_online_snapshot_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_online_snapshot_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_online_snapshot_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_online_snapshot_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_online_snapshot_test
        COMMAND cnode_online_snapshot_test)

    add_executable(cnode_v2board_online_report_test
        tests/v2board_online_report_test.cpp
        src/api/v2board/online_report.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_v2board_online_report_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api/v2board
    )
    target_link_libraries(cnode_v2board_online_report_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_v2board_online_report_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_v2board_online_report_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_v2board_online_report_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_v2board_online_report_test
        COMMAND cnode_v2board_online_report_test)

    add_test(
        NAME cnode_v2board_online_report_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/v2board_online_report_contract_test.cmake)

    add_executable(cnode_v2board_node_info_json_test
        tests/v2board_node_info_json_test.cpp
        src/api/v2board/node_info_json.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_v2board_node_info_json_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api/v2board
    )
    target_link_libraries(cnode_v2board_node_info_json_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_v2board_node_info_json_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_v2board_node_info_json_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_v2board_node_info_json_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_v2board_node_info_json_test
        COMMAND cnode_v2board_node_info_json_test)

    add_executable(cnode_v2board_user_list_json_test
        tests/v2board_user_list_json_test.cpp
        src/api/v2board/user_list_json.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_v2board_user_list_json_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/api/v2board
    )
    target_link_libraries(cnode_v2board_user_list_json_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_v2board_user_list_json_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_v2board_user_list_json_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_v2board_user_list_json_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_v2board_user_list_json_test
        COMMAND cnode_v2board_user_list_json_test)

    add_executable(cnode_anytls_outbound_settings_test
        tests/anytls_outbound_settings_test.cpp
        src/proxy/anytls/outbound/anytls_outbound_settings.cpp
        src/proxy/anytls/credentials.cpp
        src/infra/json.cpp
    )
    add_executable(cnode_substream_inbound_lifecycle_test
        tests/substream_inbound_lifecycle_test.cpp
        src/proxy/mux/inbound/mux_inbound.cpp
        src/common/mux/mux_codec.cpp
        src/proxy/uot/uot.cpp
        src/proxy/anytls/inbound/anytls_inbound.cpp
        src/proxy/anytls/anytls_codec.cpp
        src/proxy/anytls/padding.cpp
        src/proxy/anytls/credentials.cpp
        src/proxy/anytls/validator.cpp
        src/app/proxyman/inbound/factory.cpp
        src/app/proxyman/inbound/user_store.cpp
        src/transport/async_stream.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/common/sharded_user_stats.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_substream_inbound_lifecycle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls/inbound
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/mux/inbound)
    target_compile_definitions(cnode_substream_inbound_lifecycle_test PRIVATE CNODE_TEST_BUFFER_STATS)
    target_link_libraries(cnode_substream_inbound_lifecycle_test PRIVATE
        asio::asio Threads::Threads cnode_zlib crypto)
    if(WIN32)
        target_link_libraries(cnode_substream_inbound_lifecycle_test PRIVATE ws2_32)
        target_compile_definitions(cnode_substream_inbound_lifecycle_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_substream_inbound_lifecycle_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_substream_inbound_lifecycle_test COMMAND cnode_substream_inbound_lifecycle_test)
    set_tests_properties(cnode_substream_inbound_lifecycle_test PROPERTIES TIMEOUT 20)

    add_executable(cnode_anytls_codec_errors_test
        tests/anytls_codec_errors_test.cpp
        src/proxy/anytls/anytls_codec.cpp
        src/proxy/anytls/padding.cpp
        src/proxy/uot/uot.cpp
        src/transport/async_stream.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/common/sharded_user_stats.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_anytls_codec_errors_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls)
    target_link_libraries(cnode_anytls_codec_errors_test PRIVATE asio::asio Threads::Threads cnode_zlib crypto)
    target_compile_options(cnode_anytls_codec_errors_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    if(WIN32)
        target_link_libraries(cnode_anytls_codec_errors_test PRIVATE ws2_32)
        target_compile_definitions(cnode_anytls_codec_errors_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    add_test(NAME cnode_anytls_codec_errors_test COMMAND cnode_anytls_codec_errors_test)
    set_tests_properties(cnode_anytls_codec_errors_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_anytls_padding_test
        tests/anytls_padding_test.cpp
        src/proxy/anytls/padding.cpp)
    target_include_directories(cnode_anytls_padding_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls)
    target_link_libraries(cnode_anytls_padding_test PRIVATE crypto)
    target_compile_options(cnode_anytls_padding_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_anytls_padding_test COMMAND cnode_anytls_padding_test)

    add_executable(cnode_inbound_process_errors_test
        tests/inbound_process_errors_test.cpp
        src/app/proxyman/inbound/handler.cpp
        src/proxy/anytls/anytls_codec.cpp
        src/proxy/anytls/padding.cpp
        src/proxy/uot/uot.cpp
        src/transport/async_stream.cpp
        src/transport/internet/stream_settings.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/common/sharded_user_stats.cpp
        src/infra/json.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_inbound_process_errors_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls)
    target_link_libraries(cnode_inbound_process_errors_test PRIVATE asio::asio Threads::Threads cnode_zlib crypto)
    target_compile_options(cnode_inbound_process_errors_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    if(WIN32)
        target_link_libraries(cnode_inbound_process_errors_test PRIVATE ws2_32)
        target_compile_definitions(cnode_inbound_process_errors_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    add_test(NAME cnode_inbound_process_errors_test COMMAND cnode_inbound_process_errors_test)
    set_tests_properties(cnode_inbound_process_errors_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_anytls_outbound_lifecycle_test
        tests/anytls_outbound_lifecycle_test.cpp
        src/proxy/anytls/outbound/anytls_outbound.cpp
        src/proxy/anytls/outbound/anytls_outbound_settings.cpp
        src/proxy/anytls/anytls_codec.cpp
        src/proxy/anytls/padding.cpp
        src/proxy/anytls/credentials.cpp
        src/proxy/uot/uot.cpp
        src/app/proxyman/outbound/factory.cpp
        src/app/dns/dns.cpp
        src/app/dns/cache.cpp
        src/transport/async_stream.cpp
        src/transport/internet/outbound_target_builder.cpp
        src/transport/internet/outbound_bind.cpp
        src/transport/internet/stream_settings.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/infra/json.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_anytls_outbound_lifecycle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls/outbound)
    target_compile_definitions(cnode_anytls_outbound_lifecycle_test PRIVATE CNODE_TEST_BUFFER_STATS)
    target_link_libraries(cnode_anytls_outbound_lifecycle_test PRIVATE
        asio::asio Threads::Threads cnode_zlib crypto)
    if(WIN32)
        target_link_libraries(cnode_anytls_outbound_lifecycle_test PRIVATE ws2_32 iphlpapi)
        target_compile_definitions(cnode_anytls_outbound_lifecycle_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_anytls_outbound_lifecycle_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_anytls_outbound_lifecycle_test COMMAND cnode_anytls_outbound_lifecycle_test)
    set_tests_properties(cnode_anytls_outbound_lifecycle_test PROPERTIES TIMEOUT 20)

    add_executable(cnode_anytls_session_pool_test
        tests/anytls_session_pool_test.cpp
        src/common/error.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_anytls_session_pool_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls/outbound
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_anytls_session_pool_test PRIVATE
        asio::asio Threads::Threads crypto cnode_zlib)
    target_compile_definitions(cnode_anytls_session_pool_test PRIVATE
        ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING)
    if(WIN32)
        target_link_libraries(cnode_anytls_session_pool_test PRIVATE ws2_32)
        target_compile_definitions(cnode_anytls_session_pool_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_anytls_session_pool_test PRIVATE
        "$<$<CXX_COMPILER_ID:MSVC>:/FI${CMAKE_CURRENT_SOURCE_DIR}/tests/async_allocation_fault.hpp>"
        "$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-include${CMAKE_CURRENT_SOURCE_DIR}/tests/async_allocation_fault.hpp>"
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_anytls_session_pool_test COMMAND cnode_anytls_session_pool_test)
    set_tests_properties(cnode_anytls_session_pool_test PROPERTIES TIMEOUT 10)
    target_include_directories(cnode_anytls_outbound_settings_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls/outbound
    )
    target_link_libraries(cnode_anytls_outbound_settings_test PRIVATE
        asio::asio
        Threads::Threads
        crypto
    )
    if(WIN32)
        target_link_libraries(cnode_anytls_outbound_settings_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_anytls_outbound_settings_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_anytls_outbound_settings_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_anytls_outbound_settings_test
        COMMAND cnode_anytls_outbound_settings_test)

    add_executable(cnode_ss_outbound_uot_test
        tests/ss_outbound_uot_test.cpp
        src/proxy/shadowsocks/outbound/ss_outbound_uot.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_ss_outbound_uot_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/shadowsocks/outbound
    )
    target_link_libraries(cnode_ss_outbound_uot_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_ss_outbound_uot_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_ss_outbound_uot_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_ss_outbound_uot_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_ss_outbound_uot_test
        COMMAND cnode_ss_outbound_uot_test)

    add_executable(cnode_inbound_tls_policy_test
        tests/inbound_tls_policy_test.cpp
        src/transport/internet/inbound_listen.cpp
        src/transport/internet/outbound_bind.cpp
    )
    target_include_directories(cnode_inbound_tls_policy_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/service/controller
    )
    target_link_libraries(cnode_inbound_tls_policy_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_inbound_tls_policy_test PRIVATE ws2_32 iphlpapi)
        target_compile_definitions(
            cnode_inbound_tls_policy_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_inbound_tls_policy_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_inbound_tls_policy_test
        COMMAND cnode_inbound_tls_policy_test)

    add_executable(cnode_outbound_manager_test
        tests/outbound_manager_test.cpp
        src/app/proxyman/outbound/manager.cpp
    )
    target_include_directories(cnode_outbound_manager_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_outbound_manager_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_outbound_manager_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_outbound_manager_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_outbound_manager_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_outbound_manager_test
        COMMAND cnode_outbound_manager_test)

    add_executable(cnode_config_semantics_test
        tests/config_semantics_test.cpp
        src/infra/config_semantics.cpp
        src/transport/internet/inbound_listen.cpp
    )
    target_include_directories(cnode_config_semantics_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
    )
    target_link_libraries(cnode_config_semantics_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_config_semantics_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_config_semantics_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_config_semantics_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_config_semantics_test
        COMMAND cnode_config_semantics_test)

    add_executable(cnode_json_port_test
        tests/json_port_test.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_json_port_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_json_port_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_json_port_test
        COMMAND cnode_json_port_test)

    add_executable(cnode_http2_initial_window_test
        tests/http2_initial_window_test.cpp
        src/infra/http2_initial_window.cpp
        src/infra/json_unsigned.cpp
        src/infra/json.cpp
        src/transport/internet/http2_settings.cpp
    )
    target_include_directories(cnode_http2_initial_window_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_compile_options(cnode_http2_initial_window_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_http2_initial_window_test
        COMMAND cnode_http2_initial_window_test)

    add_executable(cnode_http_path_match_test
        tests/http_path_match_test.cpp
    )
    target_include_directories(cnode_http_path_match_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_compile_options(cnode_http_path_match_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_http_path_match_test
        COMMAND cnode_http_path_match_test)

    add_executable(cnode_json_unsigned_test
        tests/json_unsigned_test.cpp
        src/infra/json_unsigned.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_json_unsigned_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
    )
    target_compile_options(cnode_json_unsigned_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_json_unsigned_test
        COMMAND cnode_json_unsigned_test)

    add_executable(cnode_json_bool_test
        tests/json_bool_test.cpp
        src/infra/json_bool.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_json_bool_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
    )
    target_compile_options(cnode_json_bool_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_json_bool_test
        COMMAND cnode_json_bool_test)

    add_executable(cnode_json_object_test
        tests/json_object_test.cpp
        src/infra/json_object.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_json_object_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
    )
    target_compile_options(cnode_json_object_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_json_object_test
        COMMAND cnode_json_object_test)

    add_executable(cnode_json_string_test
        tests/json_string_test.cpp
        src/infra/json_string.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_json_string_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
    )
    target_compile_options(cnode_json_string_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_json_string_test
        COMMAND cnode_json_string_test)

    add_executable(cnode_routing_ip_network_test
        tests/routing_ip_network_test.cpp
        src/infra/routing_ip_network.cpp
    )
    target_include_directories(cnode_routing_ip_network_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_routing_ip_network_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_routing_ip_network_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_routing_ip_network_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_routing_ip_network_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_routing_ip_network_test
        COMMAND cnode_routing_ip_network_test)

    add_executable(cnode_dns_inflight_test
        tests/dns_inflight_test.cpp
        src/app/dns/dns.cpp
        src/app/dns/cache.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_dns_inflight_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_dns_inflight_test PRIVATE asio::asio Threads::Threads cnode_zlib ssl crypto)
    if(WIN32)
        target_link_libraries(cnode_dns_inflight_test PRIVATE ws2_32)
        target_compile_definitions(cnode_dns_inflight_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_dns_inflight_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_dns_inflight_test COMMAND cnode_dns_inflight_test)

    add_executable(cnode_dns_cache_test
        tests/dns_cache_test.cpp
        src/app/dns/cache.cpp
    )
    target_include_directories(cnode_dns_cache_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(cnode_dns_cache_test PRIVATE asio::asio Threads::Threads ssl crypto)
    if(WIN32)
        target_link_libraries(cnode_dns_cache_test PRIVATE ws2_32)
        target_compile_definitions(cnode_dns_cache_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_dns_cache_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_dns_cache_test COMMAND cnode_dns_cache_test)

    add_executable(cnode_dns_datagram_test
        tests/dns_datagram_test.cpp
        src/app/dns/dns.cpp
        src/app/dns/cache.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_dns_datagram_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${concurrentqueue_SOURCE_DIR})
    target_link_libraries(cnode_dns_datagram_test PRIVATE asio::asio Threads::Threads cnode_zlib ssl crypto)
    if(WIN32)
        target_link_libraries(cnode_dns_datagram_test PRIVATE ws2_32)
        target_compile_definitions(cnode_dns_datagram_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_dns_datagram_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_dns_datagram_test COMMAND cnode_dns_datagram_test)
    set_tests_properties(cnode_dns_datagram_test cnode_dns_inflight_test PROPERTIES TIMEOUT 20)

    add_executable(cnode_router_test
        tests/router_test.cpp
        src/app/router/router.cpp
        src/infra/routing_ip_network.cpp
        src/geo/geodata.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_router_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_router_test PRIVATE
        asio::asio Threads::Threads cnode_zlib
    )
    if(WIN32)
        target_link_libraries(cnode_router_test PRIVATE ws2_32)
        target_compile_definitions(cnode_router_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_router_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_router_test COMMAND cnode_router_test)

    add_executable(cnode_outbound_selection_test
        tests/outbound_selection_test.cpp
    )
    target_include_directories(cnode_outbound_selection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_options(cnode_outbound_selection_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_outbound_selection_test
        COMMAND cnode_outbound_selection_test)

    add_executable(cnode_outbound_bind_test
        tests/outbound_bind_test.cpp
        src/transport/internet/outbound_bind.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_outbound_bind_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_outbound_bind_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_outbound_bind_test PRIVATE ws2_32 iphlpapi)
        target_compile_definitions(
            cnode_outbound_bind_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_outbound_bind_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_outbound_bind_test
        COMMAND cnode_outbound_bind_test)

    add_executable(cnode_inbound_listen_test
        tests/inbound_listen_test.cpp
        src/app/worker/tcp_listener.cpp
        src/transport/internet/inbound_listen.cpp
    )
    target_include_directories(cnode_inbound_listen_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/app
    )
    target_link_libraries(cnode_inbound_listen_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_inbound_listen_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_inbound_listen_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_inbound_listen_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_inbound_listen_test
        COMMAND cnode_inbound_listen_test)

    add_executable(cnode_panel_node_ids_test
        tests/panel_node_ids_test.cpp
        src/service/controller/panel_node_ids.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_panel_node_ids_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_panel_node_ids_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_panel_node_ids_test
        COMMAND cnode_panel_node_ids_test)

    add_test(
        NAME cnode_outbound_failure_log_contract_test
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/outbound_failure_log_contract_test.cmake)

    add_executable(cnode_log_format_test
        tests/log_format_test.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_log_format_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_log_format_test PRIVATE
        Threads::Threads
        cnode_zlib
    )
    target_compile_options(cnode_log_format_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_log_format_test
        COMMAND cnode_log_format_test)

    add_executable(cnode_session_access_log_test
        tests/session_access_log_test.cpp
        src/common/session.cpp
    )
    target_include_directories(cnode_session_access_log_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_session_access_log_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_link_libraries(cnode_session_access_log_test PRIVATE ws2_32)
    endif()
    add_test(NAME cnode_session_access_log_test COMMAND cnode_session_access_log_test)

    add_test(
        NAME cnode_tcp_read_buffer_contract_test
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/tcp_read_buffer_contract_test.cmake)

    add_executable(cnode_udp_socket_owner_test
        tests/udp_socket_owner_test.cpp
        src/app/worker/udp_ingress.cpp
        src/common/session.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_udp_socket_owner_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/app
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_udp_socket_owner_test PRIVATE
        asio::asio
        Threads::Threads
        cnode_zlib
    )
    if(WIN32)
        target_link_libraries(cnode_udp_socket_owner_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_udp_socket_owner_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_udp_socket_owner_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_udp_socket_owner_test
        COMMAND cnode_udp_socket_owner_test)

    add_executable(cnode_udp_channel_test
        tests/udp_channel_test.cpp
        src/app/udp_channel.cpp
        src/app/udp_session.cpp
        src/app/udp_callback_router.cpp
        src/app/dns/dns.cpp
        src/app/dns/cache.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_udp_channel_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_udp_channel_test PRIVATE asio::asio Threads::Threads cnode_zlib crypto)
    if(WIN32)
        target_link_libraries(cnode_udp_channel_test PRIVATE ws2_32)
        target_compile_definitions(cnode_udp_channel_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_udp_channel_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(NAME cnode_udp_channel_test COMMAND cnode_udp_channel_test)
    set_tests_properties(cnode_udp_channel_test PROPERTIES TIMEOUT 30)

    add_executable(cnode_cancellation_source_test tests/cancellation_source_test.cpp)
    target_include_directories(cnode_cancellation_source_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_cancellation_source_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_compile_definitions(cnode_cancellation_source_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_cancellation_source_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_cancellation_source_test COMMAND cnode_cancellation_source_test)

    add_executable(cnode_token_bucket_test tests/token_bucket_test.cpp)
    target_include_directories(cnode_token_bucket_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_token_bucket_test PRIVATE Threads::Threads)
    target_compile_options(cnode_token_bucket_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_token_bucket_test COMMAND cnode_token_bucket_test)

    add_executable(cnode_buffer_ownership_test tests/buffer_ownership_test.cpp)
    target_include_directories(cnode_buffer_ownership_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_buffer_ownership_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_compile_definitions(cnode_buffer_ownership_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_buffer_ownership_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_buffer_ownership_test COMMAND cnode_buffer_ownership_test)

    add_executable(cnode_blake3_dispatch_test tests/blake3_dispatch_test.cpp)
    target_link_libraries(cnode_blake3_dispatch_test PRIVATE cnode_blake3)
    add_test(NAME cnode_blake3_dispatch_test COMMAND cnode_blake3_dispatch_test)

    # Exercise the fallback dispatcher independently of the build host's ISA.
    add_library(cnode_blake3_portable_test_lib STATIC
        ${blake3_SOURCE_DIR}/c/blake3.c
        ${blake3_SOURCE_DIR}/c/blake3_dispatch.c
        ${blake3_SOURCE_DIR}/c/blake3_portable.c)
    target_include_directories(cnode_blake3_portable_test_lib PUBLIC ${blake3_SOURCE_DIR}/c)
    target_compile_definitions(cnode_blake3_portable_test_lib PRIVATE
        BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)
    add_executable(cnode_blake3_portable_test tests/blake3_dispatch_test.cpp)
    target_compile_definitions(cnode_blake3_portable_test PRIVATE CNODE_EXPECT_PORTABLE)
    target_link_libraries(cnode_blake3_portable_test PRIVATE cnode_blake3_portable_test_lib)
    add_test(NAME cnode_blake3_portable_test COMMAND cnode_blake3_portable_test)

    add_executable(cnode_thread_pool_test tests/thread_pool_test.cpp)
    target_include_directories(cnode_thread_pool_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_thread_pool_test PRIVATE asio::asio Threads::Threads)
    target_compile_definitions(cnode_thread_pool_test PRIVATE
        CNODE_MEMORY_STATS CNODE_TEST_ALLOCATOR_FAULT)
    target_compile_options(cnode_thread_pool_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_thread_pool_test COMMAND cnode_thread_pool_test)

    add_executable(cnode_asio_operation_allocator_test
        tests/asio_operation_allocator_test.cpp
        src/transport/async_stream.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_asio_operation_allocator_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR})
    target_link_libraries(cnode_asio_operation_allocator_test PRIVATE asio::asio Threads::Threads cnode_zlib ssl crypto)
    if(WIN32)
        target_link_libraries(cnode_asio_operation_allocator_test PRIVATE ws2_32)
        target_compile_definitions(cnode_asio_operation_allocator_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_asio_operation_allocator_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_asio_operation_allocator_test COMMAND cnode_asio_operation_allocator_test)
    set_tests_properties(cnode_asio_operation_allocator_test PROPERTIES TIMEOUT 10)

    foreach(cache_size IN ITEMS 8 32 64)
        add_executable(cnode_asio_recycling_cache_${cache_size}_test tests/asio_recycling_cache_test.cpp)
        target_include_directories(cnode_asio_recycling_cache_${cache_size}_test PRIVATE
            ${asio_SOURCE_DIR}/asio/include)
        target_compile_definitions(cnode_asio_recycling_cache_${cache_size}_test PRIVATE
            ASIO_STANDALONE ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE=${cache_size})
        target_link_libraries(cnode_asio_recycling_cache_${cache_size}_test PRIVATE Threads::Threads)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_compile_definitions(cnode_asio_recycling_cache_${cache_size}_test PRIVATE CNODE_WRAP_ALIGNED_ALLOC)
            target_link_options(cnode_asio_recycling_cache_${cache_size}_test PRIVATE -Wl,--wrap=aligned_alloc)
        endif()
        target_compile_options(cnode_asio_recycling_cache_${cache_size}_test PRIVATE
            $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
            $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
        add_test(NAME cnode_asio_recycling_cache_${cache_size}_test
            COMMAND cnode_asio_recycling_cache_${cache_size}_test)
    endforeach()

    add_executable(cnode_tls_record_buffer_test tests/tls_record_buffer_test.cpp)
    target_include_directories(cnode_tls_record_buffer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_tls_record_buffer_test PRIVATE asio::asio Threads::Threads ssl crypto)
    if(WIN32)
        target_link_libraries(cnode_tls_record_buffer_test PRIVATE ws2_32)
        target_compile_definitions(cnode_tls_record_buffer_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_tls_record_buffer_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_tls_record_buffer_test COMMAND cnode_tls_record_buffer_test)

    add_executable(cnode_tls_bio_idle_test tests/tls_bio_idle_test.cpp)
    target_link_libraries(cnode_tls_bio_idle_test PRIVATE crypto)
    target_compile_options(cnode_tls_bio_idle_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_tls_bio_idle_test COMMAND cnode_tls_bio_idle_test)

    add_executable(cnode_relay_initial_payload_test
        tests/relay_initial_payload_test.cpp
        src/transport/async_stream.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_relay_initial_payload_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR})
    target_compile_definitions(cnode_relay_initial_payload_test PRIVATE CNODE_TEST_ALLOCATOR_FAULT)
    target_link_libraries(cnode_relay_initial_payload_test PRIVATE asio::asio Threads::Threads cnode_zlib)
    if(WIN32)
        target_link_libraries(cnode_relay_initial_payload_test PRIVATE ws2_32)
        target_compile_definitions(cnode_relay_initial_payload_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_relay_initial_payload_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_relay_initial_payload_test COMMAND cnode_relay_initial_payload_test)
    set_tests_properties(cnode_relay_initial_payload_test PROPERTIES TIMEOUT 30)
    add_test(NAME cnode_relay_full_close_test COMMAND cnode_relay_initial_payload_test --full-close)
    set_tests_properties(cnode_relay_full_close_test PROPERTIES TIMEOUT 15)

    add_executable(cnode_dispatcher_cancellation_test
        tests/dispatcher_cancellation_test.cpp
        src/transport/internet/tls_server_name.cpp
        src/app/dispatcher/default_dispatcher.cpp
        src/app/session_tracking.cpp
        src/app/dns/dns.cpp
        src/app/dns/cache.cpp
        src/transport/async_stream.cpp
        src/transport/internet/tcp_stream.cpp
        src/transport/internet/proxy_protocol.cpp
        src/transport/internet/timeout_scheduler.cpp
        src/sniff/sniffer.cpp
        src/sniff/tls_sniffer.cpp
        src/sniff/http_sniffer.cpp
        src/sniff/quic_sniffer.cpp
        src/common/error.cpp
        src/common/session.cpp
        src/infra/log.cpp)
    target_include_directories(cnode_dispatcher_cancellation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${concurrentqueue_SOURCE_DIR})
    target_link_libraries(cnode_dispatcher_cancellation_test PRIVATE asio::asio Threads::Threads cnode_zlib crypto)
    if(WIN32)
        target_link_libraries(cnode_dispatcher_cancellation_test PRIVATE ws2_32)
        target_compile_definitions(cnode_dispatcher_cancellation_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_dispatcher_cancellation_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_dispatcher_cancellation_test COMMAND cnode_dispatcher_cancellation_test)
    set_tests_properties(cnode_dispatcher_cancellation_test PROPERTIES TIMEOUT 20)

    add_executable(cnode_udp_callback_router_test
        tests/udp_callback_router_test.cpp
        src/app/udp_callback_router.cpp
    )
    target_include_directories(cnode_udp_callback_router_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/app
    )
    target_link_libraries(cnode_udp_callback_router_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_udp_callback_router_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_udp_callback_router_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_udp_callback_router_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_udp_callback_router_test
        COMMAND cnode_udp_callback_router_test)

    add_executable(cnode_xhttp_packet_session_key_test
        tests/xhttp_packet_session_key_test.cpp
    )
    target_include_directories(cnode_xhttp_packet_session_key_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_link_libraries(cnode_xhttp_packet_session_key_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_xhttp_packet_session_key_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_xhttp_packet_session_key_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_xhttp_packet_session_key_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_xhttp_packet_session_key_test
        COMMAND cnode_xhttp_packet_session_key_test)

    add_executable(cnode_xhttp_packet_queue_test
        tests/xhttp_packet_queue_test.cpp
    )
    target_include_directories(cnode_xhttp_packet_queue_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_link_libraries(cnode_xhttp_packet_queue_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_xhttp_packet_queue_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_xhttp_packet_queue_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_xhttp_packet_queue_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_xhttp_packet_queue_test
        COMMAND cnode_xhttp_packet_queue_test)

    add_executable(cnode_xhttp_upload_stream_slot_test
        tests/xhttp_upload_stream_slot_test.cpp
    )
    target_include_directories(cnode_xhttp_upload_stream_slot_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_link_libraries(cnode_xhttp_upload_stream_slot_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_xhttp_upload_stream_slot_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_xhttp_upload_stream_slot_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_xhttp_upload_stream_slot_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_xhttp_upload_stream_slot_test
        COMMAND cnode_xhttp_upload_stream_slot_test)

    add_executable(cnode_timeout_scheduler_test
        tests/timeout_scheduler_test.cpp
        tests/timeout_scheduler_new.cpp
        src/transport/internet/timeout_scheduler.cpp
    )
    target_include_directories(cnode_timeout_scheduler_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_timeout_scheduler_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_timeout_scheduler_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_timeout_scheduler_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_timeout_scheduler_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
        "$<$<CXX_COMPILER_ID:MSVC>:/FI${CMAKE_CURRENT_SOURCE_DIR}/tests/timeout_scheduler_allocation.hpp>"
        "$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-include${CMAKE_CURRENT_SOURCE_DIR}/tests/timeout_scheduler_allocation.hpp>"
    )
    add_test(
        NAME cnode_timeout_scheduler_test
        COMMAND cnode_timeout_scheduler_test)
    set_tests_properties(cnode_timeout_scheduler_test PROPERTIES TIMEOUT 10)
    add_test(
        NAME cnode_timeout_scheduler_contract_test
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/timeout_scheduler_contract_test.cmake)

    add_executable(cnode_async_write_gate_test
        tests/async_write_gate_test.cpp
    )
    target_include_directories(cnode_async_write_gate_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/internet
    )
    target_link_libraries(cnode_async_write_gate_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_async_write_gate_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_async_write_gate_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_async_write_gate_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_async_write_gate_test
        COMMAND cnode_async_write_gate_test)

    add_executable(cnode_node_transition_test
        tests/node_transition_test.cpp
        src/service/controller/node_transition.cpp
    )
    target_include_directories(cnode_node_transition_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/service/controller
    )
    target_link_libraries(cnode_node_transition_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_node_transition_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_node_transition_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_node_transition_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_node_transition_test
        COMMAND cnode_node_transition_test)

    add_executable(cnode_node_transaction_test
        tests/node_transaction_test.cpp
        src/service/controller/node_transition.cpp)
    target_include_directories(cnode_node_transaction_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/service/controller)
    target_link_libraries(cnode_node_transaction_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_link_libraries(cnode_node_transaction_test PRIVATE ws2_32)
        target_compile_definitions(cnode_node_transaction_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_node_transaction_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_node_transaction_test COMMAND cnode_node_transaction_test)
    set_tests_properties(cnode_node_transaction_test PROPERTIES TIMEOUT 10)

    add_test(
        NAME cnode_controller_transition_commit_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/controller_transition_commit_contract_test.cmake)

    add_test(
        NAME cnode_controller_worker_mutation_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/controller_worker_mutation_contract_test.cmake)

    add_executable(cnode_panel_schedule_test
        tests/panel_schedule_test.cpp
    )
    target_include_directories(cnode_panel_schedule_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/service/controller
    )
    target_compile_options(cnode_panel_schedule_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_panel_schedule_test
        COMMAND cnode_panel_schedule_test)

    add_test(
        NAME cnode_controller_panel_schedule_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/controller_panel_schedule_contract_test.cmake)

    add_test(
        NAME cnode_controller_panel_console_log_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/controller_panel_console_log_contract_test.cmake)

    add_test(
        NAME cnode_controller_monitor_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/controller_monitor_contract_test.cmake)

    add_test(
        NAME cnode_runtime_monitor_shutdown_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_monitor_shutdown_contract_test.cmake)

    add_executable(cnode_ban_tracking_contract_test
        tests/ban_tracking_contract_test.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_ban_tracking_contract_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${concurrentqueue_SOURCE_DIR}
    )
    target_link_libraries(cnode_ban_tracking_contract_test PRIVATE
        asio::asio
        Threads::Threads
        cnode_zlib
    )
    if(WIN32)
        target_link_libraries(cnode_ban_tracking_contract_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_ban_tracking_contract_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_ban_tracking_contract_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4324 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_ban_tracking_contract_test
        COMMAND cnode_ban_tracking_contract_test)

    add_executable(cnode_awaitable_batch_test
        tests/awaitable_batch_test.cpp
        src/common/awaitable_batch.cpp
    )
    target_include_directories(cnode_awaitable_batch_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    )
    target_link_libraries(cnode_awaitable_batch_test PRIVATE
        asio::asio
        Threads::Threads
    )
    # Exercise launch allocations even after an earlier case populated Asio caches.
    target_compile_definitions(cnode_awaitable_batch_test PRIVATE
        ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING)
    if(WIN32)
        target_link_libraries(cnode_awaitable_batch_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_awaitable_batch_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_awaitable_batch_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_awaitable_batch_test
        COMMAND cnode_awaitable_batch_test)
    set_tests_properties(cnode_awaitable_batch_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_awaitable_task_group_test
        tests/awaitable_task_group_test.cpp
    )
    target_include_directories(cnode_awaitable_task_group_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    )
    target_link_libraries(cnode_awaitable_task_group_test PRIVATE
        asio::asio
        Threads::Threads
    )
    # Exercise launch allocations even after an earlier case populated Asio caches.
    target_compile_definitions(cnode_awaitable_task_group_test PRIVATE
        ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING CNODE_MEMORY_STATS)
    if(WIN32)
        target_link_libraries(cnode_awaitable_task_group_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_awaitable_task_group_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_awaitable_task_group_test PRIVATE
        "$<$<CXX_COMPILER_ID:MSVC>:/FI${CMAKE_CURRENT_SOURCE_DIR}/tests/async_allocation_fault.hpp>"
        "$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-include${CMAKE_CURRENT_SOURCE_DIR}/tests/async_allocation_fault.hpp>"
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_awaitable_task_group_test
        COMMAND cnode_awaitable_task_group_test)
    set_tests_properties(cnode_awaitable_task_group_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_monitor_loop_test tests/monitor_loop_test.cpp)
    target_include_directories(cnode_monitor_loop_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(cnode_monitor_loop_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_link_libraries(cnode_monitor_loop_test PRIVATE ws2_32)
        target_compile_definitions(cnode_monitor_loop_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_monitor_loop_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_monitor_loop_test COMMAND cnode_monitor_loop_test)
    set_tests_properties(cnode_monitor_loop_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_rule_lifecycle_test
        tests/rule_lifecycle_test.cpp
        src/common/rule.cpp
    )
    target_include_directories(cnode_rule_lifecycle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_rule_lifecycle_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_rule_lifecycle_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_rule_lifecycle_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_rule_lifecycle_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_rule_lifecycle_test
        COMMAND cnode_rule_lifecycle_test)

    add_executable(cnode_worker_mailbox_test
        tests/worker_mailbox_test.cpp
    )
    target_include_directories(cnode_worker_mailbox_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_worker_mailbox_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_worker_mailbox_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_worker_mailbox_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_worker_mailbox_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_worker_mailbox_test
        COMMAND cnode_worker_mailbox_test)
    set_tests_properties(cnode_worker_mailbox_test PROPERTIES TIMEOUT 10)

    add_executable(cnode_worker_runtime_contract_test
        tests/worker_runtime_contract_test.cpp
    )
    target_include_directories(cnode_worker_runtime_contract_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_worker_runtime_contract_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_worker_runtime_contract_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_worker_runtime_contract_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_worker_runtime_contract_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_worker_runtime_contract_test
        COMMAND cnode_worker_runtime_contract_test)

    add_executable(cnode_runtime_exit_test
        tests/runtime_exit_test.cpp
    )
    target_link_libraries(cnode_runtime_exit_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_runtime_exit_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_runtime_exit_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_runtime_exit_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_forced_shutdown_test
        COMMAND cnode_runtime_exit_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/forced_shutdown_test)
    set_tests_properties(cnode_forced_shutdown_test PROPERTIES TIMEOUT 15)

    add_test(
        NAME cnode_static_inbound_startup_test
        COMMAND cnode_runtime_exit_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/runtime_startup_failure_test
            startup-failure)
    set_tests_properties(cnode_static_inbound_startup_test PROPERTIES TIMEOUT 15)

    foreach(startup_case IN ITEMS tag-collision port-collision coexist implicit)
        string(REPLACE "-" "_" startup_test "${startup_case}")
        add_test(NAME cnode_test_mode_${startup_test}_test
            COMMAND cnode_runtime_exit_test
                $<TARGET_FILE:cnode>
                ${CMAKE_CURRENT_BINARY_DIR}/test_mode_${startup_test}_test
                test-mode-${startup_case})
        set_tests_properties(cnode_test_mode_${startup_test}_test PROPERTIES
            TIMEOUT 30 RESOURCE_LOCK builtin_test_port)
    endforeach()

    foreach(PANEL_HTTP_CASE IN ITEMS replay fallback timeout)
        add_test(
            NAME cnode_panel_http_${PANEL_HTTP_CASE}_test
            COMMAND cnode_runtime_exit_test
                $<TARGET_FILE:cnode>
                ${CMAKE_CURRENT_BINARY_DIR}/panel_http_${PANEL_HTTP_CASE}_test
                panel-${PANEL_HTTP_CASE})
        set_tests_properties(cnode_panel_http_${PANEL_HTTP_CASE}_test PROPERTIES
            TIMEOUT 30)
    endforeach()

    add_test(NAME cnode_panel_heartbeat_test
        COMMAND cnode_runtime_exit_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/panel_heartbeat_test
            panel-heartbeat)
    set_tests_properties(cnode_panel_heartbeat_test PROPERTIES
        TIMEOUT 90)

    add_test(NAME cnode_panel_lifecycle_test
        COMMAND cnode_runtime_exit_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/panel_lifecycle_test
            panel-lifecycle)
    set_tests_properties(cnode_panel_lifecycle_test PROPERTIES
        TIMEOUT 110)

    add_test(NAME cnode_panel_collision_test
        COMMAND cnode_runtime_exit_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/panel_collision_test
            panel-collision)
    set_tests_properties(cnode_panel_collision_test PROPERTIES
        TIMEOUT 30)

    foreach(collision_mode IN ITEMS collision-race static-collision)
        string(REPLACE "-" "_" collision_test "${collision_mode}")
        add_test(NAME cnode_panel_${collision_test}_test
            COMMAND cnode_runtime_exit_test
                $<TARGET_FILE:cnode>
                ${CMAKE_CURRENT_BINARY_DIR}/panel_${collision_test}_test
                panel-${collision_mode})
        set_tests_properties(cnode_panel_${collision_test}_test PROPERTIES
            TIMEOUT 30)
    endforeach()

    add_test(
        NAME cnode_protocol_public_surface_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/protocol_public_surface_contract_test.cmake)

    add_test(
        NAME cnode_architecture_layering_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/architecture_layering_contract_test.cmake)

    add_test(
        NAME cnode_worker_runtime_transaction_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/worker_runtime_transaction_contract_test.cmake)

    add_executable(cnode_protocol_registration_test
        tests/protocol_registration_test.cpp
        src/app/proxyman/inbound/factory.cpp
        src/app/proxyman/inbound/user_store.cpp
        src/app/proxyman/outbound/factory.cpp
        src/infra/json.cpp
    )
    target_include_directories(cnode_protocol_registration_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/app/proxyman/outbound
    )
    target_link_libraries(cnode_protocol_registration_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_protocol_registration_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_protocol_registration_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_protocol_registration_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_protocol_registration_test
        COMMAND cnode_protocol_registration_test)

    add_executable(cnode_user_store_typed_payload_test
        tests/user_store_typed_payload_test.cpp
        src/app/proxyman/inbound/user_store.cpp
    )
    target_include_directories(cnode_user_store_typed_payload_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_user_store_typed_payload_test PRIVATE
        Threads::Threads
    )
    target_compile_options(cnode_user_store_typed_payload_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_user_store_typed_payload_test
        COMMAND cnode_user_store_typed_payload_test)

    add_executable(cnode_user_store_batch_test
        tests/user_store_batch_test.cpp
        src/app/proxyman/inbound/user_store.cpp)
    target_include_directories(cnode_user_store_batch_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_user_store_batch_test PRIVATE Threads::Threads)
    target_compile_options(cnode_user_store_batch_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_user_store_batch_test COMMAND cnode_user_store_batch_test)

    add_executable(cnode_startup_inbounds_test
        tests/startup_inbounds_test.cpp
        src/app/startup_inbounds.cpp
        src/app/proxyman/inbound/factory.cpp
        src/app/proxyman/inbound/user_store.cpp
        src/infra/config_semantics.cpp
        src/transport/internet/inbound_listen.cpp)
    target_include_directories(cnode_startup_inbounds_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src/app)
    target_link_libraries(cnode_startup_inbounds_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_link_libraries(cnode_startup_inbounds_test PRIVATE ws2_32)
        target_compile_definitions(cnode_startup_inbounds_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_startup_inbounds_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_startup_inbounds_test COMMAND cnode_startup_inbounds_test)

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        foreach(integration IN ITEMS dns_endpoint tls_cancellation)
            add_test(NAME cnode_${integration}_integration_test
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/${integration}_integration.py
                    --binary $<TARGET_FILE:cnode>
                    --output ${CMAKE_CURRENT_BINARY_DIR}/${integration}_integration_test)
            set_tests_properties(cnode_${integration}_integration_test PROPERTIES TIMEOUT 40)
        endforeach()
        add_test(NAME cnode_tls_cancellation_partial_integration_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/tls_cancellation_integration.py
                --binary $<TARGET_FILE:cnode>
                --output ${CMAKE_CURRENT_BINARY_DIR}/tls_cancellation_partial_integration_test
                --partial-record)
        set_tests_properties(cnode_tls_cancellation_partial_integration_test PROPERTIES TIMEOUT 40)
        add_test(NAME cnode_tls_coalesced_records_integration_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/tls_coalesced_records_integration.py
                --binary $<TARGET_FILE:cnode>
                --output ${CMAKE_CURRENT_BINARY_DIR}/tls_coalesced_records_integration_test)
        set_tests_properties(cnode_tls_coalesced_records_integration_test PROPERTIES TIMEOUT 35)
        add_test(NAME cnode_tls_idle_write_integration_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/tls_idle_write_integration.py
                --binary $<TARGET_FILE:cnode>
                --output ${CMAKE_CURRENT_BINARY_DIR}/tls_idle_write_integration_test)
        set_tests_properties(cnode_tls_idle_write_integration_test PROPERTIES TIMEOUT 45)
        foreach(mode IN ITEMS idle idle_partial)
            set(extra_args)
            if(mode STREQUAL "idle_partial")
                set(extra_args --partial-record --resume-record)
            endif()
            add_test(NAME cnode_tls_${mode}_integration_test
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/tls_cancellation_integration.py
                    --binary $<TARGET_FILE:cnode>
                    --output ${CMAKE_CURRENT_BINARY_DIR}/tls_${mode}_integration_test
                    --idle-seconds 12 ${extra_args})
            set_tests_properties(cnode_tls_${mode}_integration_test PROPERTIES TIMEOUT 40)
        endforeach()
        add_test(
            NAME cnode_static_inbound_outbound_integration_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/static_inbound_outbound_integration.py
                --binary $<TARGET_FILE:cnode>
                --output ${CMAKE_CURRENT_BINARY_DIR}/static_inbound_outbound_integration_test)
        set_tests_properties(cnode_static_inbound_outbound_integration_test PROPERTIES TIMEOUT 40)
        add_test(
            NAME cnode_vmess_inbound_handshake_integration_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/vmess_inbound_handshake_integration.py
                --binary $<TARGET_FILE:cnode>
                --output ${CMAKE_CURRENT_BINARY_DIR}/vmess_inbound_handshake_integration_test)
        set_tests_properties(cnode_vmess_inbound_handshake_integration_test PROPERTIES TIMEOUT 45)
        add_test(
            NAME cnode_outbound_bind_integration_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/outbound_bind_integration.py
                --binary $<TARGET_FILE:cnode>
                --output ${CMAKE_CURRENT_BINARY_DIR}/outbound_bind_integration_test)
        set_tests_properties(cnode_outbound_bind_integration_test PROPERTIES TIMEOUT 95)
    endif()

    add_executable(cnode_stream_settings_test
        tests/stream_settings_test.cpp
        src/transport/internet/stream_settings.cpp)
    target_include_directories(cnode_stream_settings_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(cnode_stream_settings_test PRIVATE asio::asio Threads::Threads)
    if(WIN32)
        target_link_libraries(cnode_stream_settings_test PRIVATE ws2_32)
        target_compile_definitions(cnode_stream_settings_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_stream_settings_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>)
    add_test(NAME cnode_stream_settings_test COMMAND cnode_stream_settings_test)

    add_test(
        NAME cnode_invalid_config_sources_test
        COMMAND ${CMAKE_COMMAND}
            "-DCNODE_EXE=$<TARGET_FILE:cnode>"
            "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/invalid_config_sources_test"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/invalid_config_sources_test.cmake)
    set_tests_properties(cnode_invalid_config_sources_test PROPERTIES RESOURCE_LOCK builtin_test_port)

    include(cmake/test_suite.cmake)
endif()

# ============================================================================
# 打印配置摘要
# ============================================================================
message(STATUS "")
message(STATUS "=== cnode Build Configuration ===")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Build Type:   ${CNODE_BUILD_TYPE_SUMMARY}")
message(STATUS "  Build Channel: ${CNODE_BUILD_CHANNEL_SUMMARY}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler:     ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Network:      standalone Asio")
message(STATUS "  Crypto:       AWS-LC")
message(STATUS "  I/O Backend:  ${CNODE_IO_BACKEND_SUMMARY}")
if(CNODE_IO_URING)
    message(STATUS "  liburing:     ${CNODE_LIBURING_TAG} (FetchContent, static)")
endif()
message(STATUS "  Allocator:    ${CNODE_ALLOCATOR_SUMMARY}")
message(STATUS "  MemoryStats:  ${CNODE_MEMORY_STATS}")
message(STATUS "  DebugSymbols: ${CNODE_RELEASE_DEBUG_SYMBOLS_SUMMARY}")
message(STATUS "  FramePointer: ${CNODE_RELEASE_FRAME_POINTERS_SUMMARY}")
message(STATUS "  LTO:          ${CNODE_LTO_SUMMARY}")
message(STATUS "")
