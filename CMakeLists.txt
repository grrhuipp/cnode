cmake_minimum_required(VERSION 3.20)

# 抑制第三方依赖的 cmake_minimum_required 过旧警告
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)

project(cnode VERSION 1.0.0 LANGUAGES C CXX)


include(FetchContent)

option(CNODE_HEAPTRACK_BUILD "Build a heaptrack-friendly glibc/system-allocator variant" OFF)
option(CNODE_AWSLC_NO_ASM "Disable AWS-LC assembly for local toolchains without nasm/perl" OFF)

if(CNODE_HEAPTRACK_BUILD)
    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} -dumpmachine
        OUTPUT_VARIABLE CNODE_COMPILER_MACHINE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(CNODE_COMPILER_MACHINE MATCHES "musl" OR
       CMAKE_CXX_COMPILER MATCHES "musl")
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

# 编译选项：使用 generator expression 区分编译器
# 警告选项移到 target_compile_options(cnode) 中，这里只设置全局优化选项

# Release 优化由 CMake 自动处理（MSVC: /O2 /Ob2 /DNDEBUG，GCC/Clang: -O3 -DNDEBUG）

# ============================================================================
# LTO（链接时优化）— Release / Profile 模式启用
#
# 效果：跨翻译单元 devirtualize final 类虚调用、内联、死代码消除
# ============================================================================
if(NOT CNODE_HEAPTRACK_BUILD)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    # Profile 模式也启用 LTO
    if(CMAKE_BUILD_TYPE STREQUAL "Profile")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
    endif()
endif()

# Profile 模式：Release 优化 + 保留符号（用于 perf/FlameGraph 性能分析）
# 注意：每个 flag 必须单独一个 generator expression，不能在一个表达式里放多个 flag
if(CMAKE_BUILD_TYPE STREQUAL "Profile")
    add_compile_options(
        $<$<CXX_COMPILER_ID:MSVC>:/O2>
        $<$<CXX_COMPILER_ID:MSVC>:/Zi>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O3>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-g>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-fno-omit-frame-pointer>
    )
    add_compile_definitions(NDEBUG)
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
target_compile_definitions(asio_standalone INTERFACE ASIO_STANDALONE)

set(BUILD_TESTING OFF CACHE BOOL "Disable third-party tests" FORCE)
set(BUILD_TOOL OFF CACHE BOOL "Disable AWS-LC bssl tool" FORCE)
set(DISABLE_GO ON CACHE BOOL "Disable AWS-LC Go helpers" FORCE)
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

find_package(Threads REQUIRED)
message(STATUS "Allocator: system")

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
    cnode_zlib
)

# 构建版本号：优先使用外部传入的 BUILD_ID，否则生成随机 hex
if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(RANDOM LENGTH 12 ALPHABET "0123456789abcdef" BUILD_ID)
endif()
if(CNODE_HEAPTRACK_BUILD)
    set(BUILD_CHANNEL "heaptrack")
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BUILD_CHANNEL "debug")
else()
    set(BUILD_CHANNEL "release")
endif()
target_compile_definitions(cnode PRIVATE BUILD_ID="${BUILD_ID}" BUILD_CHANNEL="${BUILD_CHANNEL}")
message(STATUS "Build ID: ${BUILD_ID}")
message(STATUS "Build Channel: ${BUILD_CHANNEL}")

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

# ============================================================================
# 打印配置摘要
# ============================================================================
message(STATUS "")
message(STATUS "=== cnode Build Configuration ===")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Build Type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler:     ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Network:      standalone Asio")
message(STATUS "  Crypto:       AWS-LC")
if(WIN32)
    message(STATUS "  I/O Backend:  IOCP")
else()
    message(STATUS "  I/O Backend:  epoll")
endif()
message(STATUS "  Allocator:    system")
message(STATUS "  MemoryStats:  ${CNODE_MEMORY_STATS}")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION OR CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE)
    message(STATUS "  LTO:          enabled")
else()
    message(STATUS "  LTO:          disabled")
endif()
message(STATUS "")
