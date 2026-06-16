cmake_minimum_required(VERSION 3.20)

# 抑制第三方依赖的 cmake_minimum_required 过旧警告
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

project(cnode VERSION 1.0.0 LANGUAGES C CXX)

include(FetchContent)

option(CNODE_HEAPTRACK_BUILD "Build a heaptrack-friendly glibc/system-allocator variant" OFF)
option(CNODE_AWSLC_NO_ASM "Disable AWS-LC assembly for local toolchains without nasm/perl" OFF)
option(CNODE_IO_URING "Use Asio io_uring backend on Linux" OFF)
option(CNODE_RELEASE_DEBUG_SYMBOLS "Emit debug info for Release builds so CI can split .debug symbol files" ON)
option(CNODE_RELEASE_FRAME_POINTERS "Keep frame pointers in Release builds for perf/heaptrack symbolization" ON)
option(CNODE_MIMALLOC_MUSL "Use mimalloc for global C++ new/delete in musl builds" ON)
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
if(NOT CNODE_HEAPTRACK_BUILD)
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

option(CNODE_MEMORY_STATS "Enable runtime live/peak memory object counters" ON)

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
)
FetchContent_MakeAvailable(aws_lc)
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
)
FetchContent_GetProperties(blake3)
if(NOT blake3_POPULATED)
    FetchContent_Populate(blake3)
endif()
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
    src/infra/json.cpp
    src/infra/config.cpp
    src/infra/config_loader.cpp
    src/infra/config_validation.cpp

    # App - DNS
    src/app/dns/dns.cpp
    src/app/dns/cache.cpp
    src/app/dns/global_cache.cpp

    # Geo
    src/geo/geodata.cpp

    # Transport - common stream interface
    src/transport/async_stream.cpp

    # Transport - Internet
    src/transport/internet/tcp_stream.cpp
    src/transport/internet/timeout_scheduler.cpp
    src/transport/internet/tls_stream.cpp
    src/transport/internet/ws_stream.cpp
    src/transport/internet/transport_stack.cpp
    src/transport/internet/transport_dialer.cpp
    src/transport/internet/outbound_target_builder.cpp
    src/transport/internet/proxy_protocol.cpp

    # App (Application layer)
    src/app/dispatcher/default_dispatcher.cpp
    src/app/proxyman/inbound/factory.cpp
    src/app/proxyman/inbound/handler.cpp
    src/app/proxyman/inbound/manager.cpp
    src/app/proxyman/inbound/tcp_worker.cpp
    src/app/proxyman/inbound/udp_worker.cpp
    src/app/proxyman/inbound/user_store.cpp
    src/app/proxyman/outbound/factory.cpp
    src/app/proxyman/outbound/source_config.cpp
    src/app/proxyman/outbound/handler.cpp
    src/app/proxyman/outbound/manager.cpp
    src/app/worker.cpp
    src/service/controller/controller.cpp
    src/service/controller/config.cpp
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
    src/proxy/vless/inbound/vless_inbound.cpp
    src/proxy/vless/outbound/vless_outbound.cpp

    # Proxy - Trojan
    src/proxy/trojan/validator.cpp
    src/proxy/trojan/trojan_codec.cpp
    src/proxy/trojan/inbound/trojan_inbound.cpp
    src/proxy/trojan/outbound/trojan_outbound.cpp

    # Proxy - Shadowsocks
    src/proxy/shadowsocks/client.cpp
    src/proxy/shadowsocks/server.cpp
    src/proxy/shadowsocks/validator.cpp
    src/proxy/shadowsocks/shadowsocks_protocol.cpp
    src/proxy/shadowsocks/ss_udp.cpp
    src/proxy/shadowsocks/inbound/ss_inbound.cpp
    src/proxy/shadowsocks/outbound/ss_outbound.cpp

    # Proxy - AnyTLS
    src/proxy/anytls/anytls_codec.cpp
    src/proxy/anytls/validator.cpp
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
    target_link_libraries(cnode PRIVATE ws2_32 mswsock psapi)
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

if(CNODE_HEAPTRACK_BUILD)
    set(CNODE_LTO_SUMMARY "disabled")
elseif(CNODE_IS_MULTI_CONFIG)
    set(CNODE_LTO_SUMMARY "Release config")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CNODE_LTO_SUMMARY "enabled")
else()
    set(CNODE_LTO_SUMMARY "disabled")
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
message(STATUS "  DebugSymbols: ${CNODE_RELEASE_DEBUG_SYMBOLS}")
message(STATUS "  FramePointer: ${CNODE_RELEASE_FRAME_POINTERS}")
message(STATUS "  LTO:          ${CNODE_LTO_SUMMARY}")
message(STATUS "")
