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
option(CNODE_MIMALLOC_MUSL "Use mimalloc for global C++ new/delete in musl builds" ON)
option(CNODE_BUILD_TESTS "Build cnode unit tests" OFF)
set(CNODE_ASIO_RECYCLING_CACHE_SIZE 8 CACHE STRING "Asio small-block recycling cache size")
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

set(CNODE_USE_MIMALLOC OFF)
if(CNODE_MIMALLOC_MUSL AND CNODE_TARGET_IS_MUSL AND NOT CNODE_HEAPTRACK_BUILD)
    set(CNODE_USE_MIMALLOC ON)
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
target_compile_definitions(cnode_blake3 PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
)
message(STATUS "Using BLAKE3 via FetchContent")

FetchContent_Declare(
    zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG v1.5.7
    SOURCE_SUBDIR cnode-no-upstream-cmake
)
FetchContent_MakeAvailable(zstd)
add_library(cnode_zstd STATIC
    ${zstd_SOURCE_DIR}/lib/common/debug.c
    ${zstd_SOURCE_DIR}/lib/common/entropy_common.c
    ${zstd_SOURCE_DIR}/lib/common/error_private.c
    ${zstd_SOURCE_DIR}/lib/common/fse_decompress.c
    ${zstd_SOURCE_DIR}/lib/common/pool.c
    ${zstd_SOURCE_DIR}/lib/common/threading.c
    ${zstd_SOURCE_DIR}/lib/common/xxhash.c
    ${zstd_SOURCE_DIR}/lib/common/zstd_common.c
    ${zstd_SOURCE_DIR}/lib/compress/fse_compress.c
    ${zstd_SOURCE_DIR}/lib/compress/hist.c
    ${zstd_SOURCE_DIR}/lib/compress/huf_compress.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_compress.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_compress_literals.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_compress_sequences.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_compress_superblock.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_double_fast.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_fast.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_lazy.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_ldm.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_opt.c
    ${zstd_SOURCE_DIR}/lib/compress/zstd_preSplit.c
    ${zstd_SOURCE_DIR}/lib/compress/zstdmt_compress.c
)
target_include_directories(cnode_zstd PUBLIC ${zstd_SOURCE_DIR}/lib)
message(STATUS "Using zstd compression library via FetchContent")

if(CNODE_USE_MIMALLOC)
    set(MI_OVERRIDE ON CACHE BOOL "Override malloc/free so C++ new/delete reaches mimalloc through libstdc++" FORCE)
    set(MI_LIBC_MUSL ON CACHE BOOL "Build mimalloc for musl libc" FORCE)
    set(MI_BUILD_SHARED OFF CACHE BOOL "Disable mimalloc shared library" FORCE)
    set(MI_BUILD_STATIC ON CACHE BOOL "Build mimalloc static library" FORCE)
    set(MI_BUILD_OBJECT OFF CACHE BOOL "Disable mimalloc object library" FORCE)
    set(MI_BUILD_TESTS OFF CACHE BOOL "Disable mimalloc tests" FORCE)
    FetchContent_Declare(
        mimalloc
        GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
        GIT_TAG v2.1.7
    )
    FetchContent_MakeAvailable(mimalloc)
    if(NOT TARGET mimalloc-static)
        message(FATAL_ERROR "mimalloc-static target is required for CNODE_USE_MIMALLOC")
    endif()
    message(STATUS "Using mimalloc MI_OVERRIDE on musl")
endif()

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
if(CNODE_USE_MIMALLOC)
    set(CNODE_ALLOCATOR_SUMMARY "mimalloc (MI_OVERRIDE)")
else()
    set(CNODE_ALLOCATOR_SUMMARY "system")
endif()
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
    src/infra/access_log_identity.cpp
    src/infra/access_log_encoding.cpp
    src/infra/access_log_reporter.cpp
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

    # App - DNS
    src/app/dns/dns.cpp
    src/app/dns/cache.cpp
    src/app/dns/global_cache.cpp

    # Geo
    src/geo/geodata.cpp

    # Transport - common stream interface
    src/transport/async_stream.cpp
    src/transport/internet/inbound_listen.cpp
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
    src/transport/internet/tls_context_cache_key.cpp
    src/transport/internet/transport_stack.cpp
    src/transport/internet/transport_dialer.cpp
    src/transport/internet/outbound_target_builder.cpp
    src/transport/internet/proxy_protocol.cpp

    # App (Application layer)
    src/app/access_log_session.cpp
    src/app/dispatcher/default_dispatcher.cpp
    src/app/mux_session_handler.cpp
    src/app/proxyman/inbound/factory.cpp
    src/app/proxyman/inbound/handler.cpp
    src/app/proxyman/inbound/manager.cpp
    src/app/proxyman/inbound/tcp_worker.cpp
    src/app/proxyman/inbound/udp_worker.cpp
    src/app/proxyman/inbound/user_store.cpp
    src/app/proxyman/outbound/factory.cpp
    src/app/proxyman/outbound/source_config.cpp
    src/app/proxyman/outbound/manager.cpp
    src/app/worker.cpp
    src/service/controller/controller.cpp
    src/service/controller/awaitable_batch.cpp
    src/service/controller/node_transition.cpp
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
    src/app/static_inbound_runtime.cpp
    src/app/relay_udp.cpp        # DoUDPRelay (UDP)
    src/app/session_tracking.cpp
    src/common/mux/mux_relay.cpp
    src/common/rule.cpp
    src/common/session.cpp
    src/common/sharded_user_stats.cpp
    src/app/stats.cpp
    src/app/udp_session.cpp
    src/app/bootstrap.cpp

    # Sniff
    src/sniff/sniffer.cpp
    src/sniff/tls_sniffer.cpp
    src/sniff/http_sniffer.cpp

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
    src/proxy/vless/vless_codec.cpp
    src/proxy/vless/vless_encryption.cpp
    src/proxy/vless/vless_encryption_crypto.cpp
    src/proxy/vless/vless_encryption_handshake.cpp
    src/proxy/vless/vless_encryption_io.cpp
    src/proxy/vless/vless_encryption_record.cpp
    src/proxy/vless/vless_encryption_runtime.cpp
    src/proxy/vless/vless_encryption_xor.cpp
    src/proxy/vless/vless_vision.cpp
    src/proxy/vless/inbound/vless_inbound.cpp
    src/proxy/vless/outbound/vless_outbound.cpp

    # Proxy - Trojan
    src/proxy/trojan/validator.cpp
    src/proxy/trojan/trojan_codec.cpp
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

    # Proxy - AnyTLS
    src/proxy/anytls/anytls_codec.cpp
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
    cnode_zstd
)

if(CNODE_USE_MIMALLOC)
    target_link_libraries(cnode PRIVATE mimalloc-static)
endif()

if(CNODE_IO_URING)
    target_compile_definitions(cnode PRIVATE CNODE_IO_URING_ENABLED)
    add_dependencies(cnode cnode_liburing_static)
    target_link_libraries(cnode PRIVATE "${CNODE_LIBURING_LIBRARY}")
endif()

# 构建版本号：优先使用外部传入的 BUILD_ID，否则使用 UTC 时间戳
if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(TIMESTAMP BUILD_ID "%Y%m%dT%H%M%SZ" UTC)
endif()
if(CNODE_HEAPTRACK_BUILD)
    set(CNODE_BUILD_CHANNEL "heaptrack")
else()
    set(CNODE_BUILD_CHANNEL "$<IF:$<CONFIG:Debug>,debug,release>")
endif()
target_compile_definitions(cnode PRIVATE
    BUILD_ID="${BUILD_ID}"
    BUILD_CHANNEL="${CNODE_BUILD_CHANNEL}"
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
    target_link_libraries(cnode PRIVATE ws2_32 mswsock psapi crypt32)
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
        src/infra/json.cpp
    )
    target_include_directories(cnode_anytls_outbound_settings_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/anytls/outbound
    )
    target_link_libraries(cnode_anytls_outbound_settings_test PRIVATE
        asio::asio
        Threads::Threads
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
        target_link_libraries(cnode_inbound_tls_policy_test PRIVATE ws2_32)
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

    add_executable(cnode_outbound_bind_test
        tests/outbound_bind_test.cpp
        src/transport/internet/outbound_bind.cpp
    )
    target_include_directories(cnode_outbound_bind_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_outbound_bind_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_outbound_bind_test PRIVATE ws2_32)
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
        src/app/proxyman/inbound/tcp_worker.cpp
        src/transport/internet/inbound_listen.cpp
    )
    target_include_directories(cnode_inbound_listen_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
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

    add_executable(cnode_access_log_wire_test
        tests/access_log_wire_test.cpp
        src/infra/access_log_identity.cpp
        src/infra/access_log_encoding.cpp
    )
    target_include_directories(cnode_access_log_wire_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra
    )
    target_link_libraries(cnode_access_log_wire_test PRIVATE
        asio::asio
        cnode_zstd
    )
    if(WIN32)
        target_link_libraries(cnode_access_log_wire_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_access_log_wire_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_access_log_wire_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_access_log_wire_test
        COMMAND cnode_access_log_wire_test)

    add_executable(cnode_udp_socket_owner_test
        tests/udp_socket_owner_test.cpp
        src/app/proxyman/inbound/udp_worker.cpp
        src/common/session.cpp
        src/infra/log.cpp
    )
    target_include_directories(cnode_udp_socket_owner_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
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

    add_executable(cnode_static_inbound_startup_test
        tests/static_inbound_startup_test.cpp
    )
    target_link_libraries(cnode_static_inbound_startup_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_static_inbound_startup_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_static_inbound_startup_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_static_inbound_startup_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_static_inbound_startup_test
        COMMAND cnode_static_inbound_startup_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/static_inbound_startup_test)
    set_tests_properties(cnode_static_inbound_startup_test PROPERTIES TIMEOUT 15)

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
        src/service/controller/awaitable_batch.cpp
    )
    target_include_directories(cnode_awaitable_batch_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/service/controller
    )
    target_link_libraries(cnode_awaitable_batch_test PRIVATE
        asio::asio
        Threads::Threads
    )
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

    add_executable(cnode_rule_lifecycle_test
        tests/rule_lifecycle_test.cpp
        src/common/rule.cpp
    )
    target_include_directories(cnode_rule_lifecycle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_compile_options(cnode_rule_lifecycle_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_rule_lifecycle_test
        COMMAND cnode_rule_lifecycle_test)

    add_executable(cnode_worker_shutdown_contract_test
        tests/worker_shutdown_contract_test.cpp
    )
    target_include_directories(cnode_worker_shutdown_contract_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cnode_worker_shutdown_contract_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_worker_shutdown_contract_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_worker_shutdown_contract_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_worker_shutdown_contract_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_worker_shutdown_contract_test
        COMMAND cnode_worker_shutdown_contract_test)

    add_executable(cnode_graceful_shutdown_test
        tests/graceful_shutdown_test.cpp
    )
    target_link_libraries(cnode_graceful_shutdown_test PRIVATE
        asio::asio
        Threads::Threads
    )
    if(WIN32)
        target_link_libraries(cnode_graceful_shutdown_test PRIVATE ws2_32)
        target_compile_definitions(
            cnode_graceful_shutdown_test PRIVATE _WIN32_WINNT=0x0A00)
    endif()
    target_compile_options(cnode_graceful_shutdown_test PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /Zc:preprocessor>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
    )
    add_test(
        NAME cnode_graceful_shutdown_test
        COMMAND cnode_graceful_shutdown_test
            $<TARGET_FILE:cnode>
            ${CMAKE_CURRENT_BINARY_DIR}/graceful_shutdown_test)
    set_tests_properties(cnode_graceful_shutdown_test PROPERTIES TIMEOUT 15)

    add_test(
        NAME cnode_protocol_public_surface_contract_test
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/protocol_public_surface_contract_test.cmake)

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

    add_test(
        NAME cnode_invalid_config_sources_test
        COMMAND ${CMAKE_COMMAND}
            "-DCNODE_EXE=$<TARGET_FILE:cnode>"
            "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/invalid_config_sources_test"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/invalid_config_sources_test.cmake)

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
