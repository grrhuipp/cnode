cmake_minimum_required(VERSION 3.20)

# 抑制第三方依赖的 cmake_minimum_required 过旧警告
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)

# ============================================================================
# vcpkg 自动集成（须在 project() 之前）
# ============================================================================
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# vcpkg triplet - 完全静态链接
if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    if(DEFINED ENV{VCPKG_DEFAULT_TRIPLET})
        set(VCPKG_TARGET_TRIPLET "$ENV{VCPKG_DEFAULT_TRIPLET}" CACHE STRING "")
    elseif(WIN32)
        set(VCPKG_TARGET_TRIPLET "x64-windows-static-md" CACHE STRING "")
    endif()
endif()
if(DEFINED ENV{VCPKG_DEFAULT_HOST_TRIPLET} AND NOT DEFINED VCPKG_HOST_TRIPLET)
    set(VCPKG_HOST_TRIPLET "$ENV{VCPKG_DEFAULT_HOST_TRIPLET}" CACHE STRING "")
endif()

project(cnode VERSION 1.0.0 LANGUAGES CXX)

enable_testing()

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
# Sanitizer 模式自动跳过（LTO 与 ASan/TSan 诊断信息冲突）
# ============================================================================
if(NOT SANITIZER)
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

# ============================================================================
# ISSUE-02-01: Sanitizer 支持（ASan / UBSan / TSan）
#
# 使用方法：
#   cmake -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=asan ..
#   cmake -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=ubsan ..
#   cmake -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=tsan ..
#   cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSANITIZER=asan ..
#
# 压测命令：
#   ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./cnode -c config.json
#   运行 >= 30 分钟，确保 ASan/UBSan 零报错
# ============================================================================
set(SANITIZER "" CACHE STRING "Enable sanitizer (asan, ubsan, tsan, msan)")

if(SANITIZER)
    message(STATUS "Sanitizer enabled: ${SANITIZER}")

    # 定义调试宏
    add_compile_definitions(ACPP_DEBUG)

    if(SANITIZER STREQUAL "asan")
        # AddressSanitizer: 检测内存错误（UAF、堆溢出、栈溢出、内存泄漏）
        if(MSVC)
            add_compile_options(/fsanitize=address /Zi)
            add_link_options(/fsanitize=address)
        else()
            add_compile_options(-fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls -g)
            add_link_options(-fsanitize=address)
        endif()
        message(STATUS "  - ASan: Use-After-Free, heap/stack overflow, memory leak detection")
        message(STATUS "  - Run with: ASAN_OPTIONS=detect_leaks=1:abort_on_error=1")

    elseif(SANITIZER STREQUAL "ubsan")
        # UndefinedBehaviorSanitizer: 检测未定义行为（MSVC 不支持 UBSan）
        if(MSVC)
            message(WARNING "UBSan is not supported by MSVC, ignoring")
        else()
            add_compile_options(-fsanitize=undefined -fsanitize=float-divide-by-zero -fsanitize=integer -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
            add_link_options(-fsanitize=undefined)
        endif()
        message(STATUS "  - UBSan: signed overflow, null pointer, misaligned access, etc.")
        message(STATUS "  - Run with: UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")

    elseif(SANITIZER STREQUAL "tsan")
        # ThreadSanitizer: 检测数据竞争（MSVC 不支持 TSan）
        if(MSVC)
            message(WARNING "TSan is not supported by MSVC, ignoring")
        else()
            add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
            add_link_options(-fsanitize=thread)
        endif()
        message(STATUS "  - TSan: data race detection")
        message(STATUS "  - Run with: TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1")

    elseif(SANITIZER STREQUAL "msan")
        # MemorySanitizer: 检测未初始化内存读取（仅 Clang 支持）
        if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            add_compile_options(
                -fsanitize=memory
                -fsanitize-memory-track-origins=2
                -fno-omit-frame-pointer
                -g
            )
            add_link_options(-fsanitize=memory)
            message(STATUS "  - MSan: uninitialized memory read detection")
        else()
            message(WARNING "MSan is only supported by Clang, ignoring")
        endif()

    else()
        message(WARNING "Unknown sanitizer: ${SANITIZER}, ignoring")
    endif()
endif()

# ============================================================================
# 依赖查找
# ============================================================================

# standalone Asio（via vcpkg）
find_package(asio CONFIG REQUIRED)

# Threads
find_package(Threads REQUIRED)

# OpenSSL（via vcpkg）
find_package(OpenSSL REQUIRED)
message(STATUS "Using OpenSSL via vcpkg")

# zlib (用于 CRC32)（via vcpkg）
find_package(ZLIB REQUIRED)

# ============================================================================
# mimalloc 高性能内存分配器（via vcpkg）
# 注意：mimalloc 与 ASan/MSan/TSan 不兼容，启用 Sanitizer 时自动禁用
# ============================================================================
option(USE_MIMALLOC "Use mimalloc as default memory allocator" ON)
option(CNODE_MEMORY_STATS "Enable runtime live/peak memory object counters" OFF)

if(USE_MIMALLOC AND SANITIZER)
    message(WARNING "mimalloc is incompatible with sanitizers, disabling mimalloc")
    set(USE_MIMALLOC OFF)
endif()

if(USE_MIMALLOC)
    find_package(mimalloc CONFIG REQUIRED)
    set(HAS_MIMALLOC TRUE)
    message(STATUS "Found mimalloc ${mimalloc_VERSION}")
else()
    set(HAS_MIMALLOC FALSE)
    if(SANITIZER)
        message(STATUS "mimalloc: DISABLED (incompatible with ${SANITIZER})")
    else()
        message(STATUS "mimalloc: DISABLED (using system allocator)")
    endif()
endif()

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
    src/transport/internet/proxy_protocol.cpp

    # App (Application layer)
    src/app/dispatcher/default_dispatcher.cpp
    src/app/proxyman/inbound/factory.cpp
    src/app/proxyman/inbound/handler.cpp
    src/app/proxyman/inbound/manager.cpp
    src/app/proxyman/inbound/tcp_worker.cpp
    src/app/proxyman/inbound/udp_worker.cpp
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
)

target_link_libraries(cnode PRIVATE
    asio::asio
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

# 构建版本号：优先使用外部传入的 BUILD_ID，否则生成随机 hex
if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(RANDOM LENGTH 12 ALPHABET "0123456789abcdef" BUILD_ID)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
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

# 条件链接 mimalloc（必须早于其他库以覆盖 malloc/new）
if(HAS_MIMALLOC)
    target_link_libraries(cnode PRIVATE mimalloc-static)
    target_compile_definitions(cnode PRIVATE USE_MIMALLOC)
    message(STATUS "Linking mimalloc-static for malloc override")
endif()

# 预编译头（PCH）- 加速 Asio/OpenSSL/标准库模板的编译
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


add_test(
    NAME no_worker_direct_validator_access
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_direct_validator_access.cmake
)

add_test(
    NAME no_worker_direct_udp_outbound_dispatch
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_direct_udp_outbound_dispatch.cmake
)

add_test(
    NAME no_worker_shadowsocks_udp_codec
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_shadowsocks_udp_codec.cmake
)

add_test(
    NAME no_worker_relay_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_relay_api.cmake
)

add_test(
    NAME no_dispatcher_direct_relay_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dispatcher_direct_relay_api.cmake
)


add_test(
    NAME no_parsed_action_handoff
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_parsed_action_handoff.cmake
)


add_test(
    NAME no_relay_wrapper_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_relay_wrapper_api.cmake
)


add_test(
    NAME no_dispatcher_protocol_includes
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dispatcher_protocol_includes.cmake
)


add_test(
    NAME no_routing_dispatcher_relay_coupling
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_routing_dispatcher_relay_coupling.cmake
)


add_test(
    NAME no_dispatch_request_carrier
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dispatch_request_carrier.cmake
)

add_test(
    NAME no_protocol_stream_wrapper_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_protocol_stream_wrapper_api.cmake
)

add_test(
    NAME no_protocol_named_handler_classes
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_protocol_named_handler_classes.cmake
)

add_test(
    NAME no_proxyman_inbound_protocol_udp_types
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_proxyman_inbound_protocol_udp_types.cmake
)

add_test(
    NAME no_public_shadowsocks_udp_codec_header
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_shadowsocks_udp_codec_header.cmake
)

add_test(
    NAME no_public_trojan_codec_header
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_trojan_codec_header.cmake
)

add_test(
    NAME no_public_vmess_cipher_header
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_vmess_cipher_header.cmake
)

add_test(
    NAME no_public_vmess_crypto_header
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_vmess_crypto_header.cmake
)

add_test(
    NAME no_public_vmess_request_header
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_vmess_request_header.cmake
)

add_test(
    NAME no_public_shadowsocks_aead_cipher_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_shadowsocks_aead_cipher_api.cmake
)

add_test(
    NAME no_relay_protocol_specific_names
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_relay_protocol_specific_names.cmake
)

add_test(
    NAME no_trojan_udp_persistent_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_trojan_udp_persistent_bytevector.cmake
)

add_test(
    NAME no_udp_reply_queue_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_udp_reply_queue_bytevector.cmake
)

add_test(
    NAME no_mux_reply_queue_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_mux_reply_queue_bytevector.cmake
)

add_test(
    NAME no_mux_frame_buffer_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_mux_frame_buffer_bytevector.cmake
)

add_test(
    NAME no_vmess_request_pending_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_vmess_request_pending_bytevector.cmake
)

add_test(
    NAME no_udp_relay_reply_queue_packet
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_udp_relay_reply_queue_packet.cmake
)

add_test(
    NAME no_trojan_udp_queue_packet
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_trojan_udp_queue_packet.cmake
)

add_test(
    NAME no_public_owned_udp_packet_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_owned_udp_packet_bytevector.cmake
)

add_test(
    NAME no_public_udp_decode_result_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_udp_decode_result_bytevector.cmake
)

add_test(
    NAME no_tcp_stream_pending_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_tcp_stream_pending_bytevector.cmake
)

add_test(
    NAME no_trojan_udp_codec_packet_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_trojan_udp_codec_packet_bytevector.cmake
)

add_test(
    NAME no_initial_payload_bytevector_overflow
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_initial_payload_bytevector_overflow.cmake
)

add_test(
    NAME no_mux_codec_return_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_mux_codec_return_bytevector.cmake
)

add_test(
    NAME no_shadowsocks_udp_decode_result_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_shadowsocks_udp_decode_result_bytevector.cmake
)

add_test(
    NAME no_protocol_udp_return_bytevector_builders
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_protocol_udp_return_bytevector_builders.cmake
)

add_test(
    NAME no_trojan_request_payload_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_trojan_request_payload_bytevector.cmake
)

add_test(
    NAME no_dns_query_return_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dns_query_return_bytevector.cmake
)

add_test(
    NAME no_worker_udp_response_bytevector
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_udp_response_bytevector.cmake
)

add_test(
    NAME no_ws_stream_circular_pending_buffer
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_ws_stream_circular_pending_buffer.cmake
)

add_test(
    NAME no_common_circular_buffer_header
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_common_circular_buffer_header.cmake
)

add_test(
    NAME no_multibuffer_public_threadlocal_spill
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_multibuffer_public_threadlocal_spill.cmake
)

add_test(
    NAME no_runtime_config_xrayr_path_fields
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_runtime_config_xrayr_path_fields.cmake
)

add_test(
    NAME no_worker_direct_config_runtime
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_direct_config_runtime.cmake
)

add_test(
    NAME no_runtime_config_raw_panel_json
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_runtime_config_raw_panel_json.cmake
)

add_test(
    NAME no_static_inbound_setup_raw_json
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_static_inbound_setup_raw_json.cmake
)

add_test(
    NAME no_worker_runtime_outbound_config_json
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_runtime_outbound_config_json.cmake
)

add_test(
    NAME no_controller_outbound_builder_raw_json
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_controller_outbound_builder_raw_json.cmake
)

add_test(
    NAME no_bootstrap_inbounds_raw_settings
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_bootstrap_inbounds_raw_settings.cmake
)

add_test(
    NAME no_worker_header_infra_config_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_header_infra_config_dependency.cmake
)

add_test(
    NAME no_worker_runtime_full_config_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_runtime_full_config_dependency.cmake
)

add_test(
    NAME no_hot_path_public_config_header_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_hot_path_public_config_header_dependency.cmake
)

add_test(
    NAME no_hot_path_public_common_umbrella_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_hot_path_public_common_umbrella_dependency.cmake
)

add_test(
    NAME no_config_types_common_umbrella_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_types_common_umbrella_dependency.cmake
)

add_test(
    NAME default_config_json_layout
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/default_config_json_layout.cmake
)

add_test(
    NAME no_stream_settings_tls_stream_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_stream_settings_tls_stream_dependency.cmake
)

add_test(
    NAME no_hot_path_cpp_config_class_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_hot_path_cpp_config_class_dependency.cmake
)

add_test(
    NAME no_inbound_factory_raw_settings_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_inbound_factory_raw_settings_api.cmake
)

add_test(
    NAME no_static_inbound_runtime_raw_settings
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_static_inbound_runtime_raw_settings.cmake
)

add_test(
    NAME no_static_inbound_runtime_inbound_config_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_static_inbound_runtime_inbound_config_api.cmake
)

add_test(
    NAME no_static_inbound_runtime_public_config_types_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_static_inbound_runtime_public_config_types_dependency.cmake
)

add_test(
    NAME no_static_inbound_prepared_config_full_config_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_static_inbound_prepared_config_full_config_dependency.cmake
)

add_test(
    NAME no_config_loader_builtin_outbound_raw_settings
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_loader_builtin_outbound_raw_settings.cmake
)

add_test(
    NAME no_config_public_raw_inbounds_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_public_raw_inbounds_api.cmake
)

add_test(
    NAME no_config_runtime_raw_inbounds_storage
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_runtime_raw_inbounds_storage.cmake
)

add_test(
    NAME no_public_raw_inbound_config_type
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_raw_inbound_config_type.cmake
)

add_test(
    NAME no_config_public_raw_outbounds_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_public_raw_outbounds_api.cmake
)

add_test(
    NAME no_config_runtime_raw_outbounds_storage
    COMMAND ${CMAKE_COMMAND}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_runtime_raw_outbounds_storage.cmake
)

add_test(
    NAME no_public_raw_outbound_config_type
    COMMAND ${CMAKE_COMMAND}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_raw_outbound_config_type.cmake
)

add_test(
    NAME no_worker_split_timeout_runtime_state
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_split_timeout_runtime_state.cmake
)

add_test(
    NAME no_worker_split_pressure_runtime_state
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_split_pressure_runtime_state.cmake
)

add_test(
    NAME no_worker_non_atomic_runtime_snapshot
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_non_atomic_runtime_snapshot.cmake
)

add_test(
    NAME no_dynamic_outbound_without_snapshot_replace
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dynamic_outbound_without_snapshot_replace.cmake
)

add_test(
    NAME no_static_inbounds_outside_runtime_snapshot
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_static_inbounds_outside_runtime_snapshot.cmake
)

add_test(
    NAME no_public_outbound_source_config_raw_json
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_outbound_source_config_raw_json.cmake
)

add_test(
    NAME no_public_outbound_factory_source_prepare_api
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_outbound_factory_source_prepare_api.cmake
)

add_test(
    NAME no_public_outbound_headers_raw_source_names
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_outbound_headers_raw_source_names.cmake
)

add_test(
    NAME no_rule_manager_in_place_rule_update
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_rule_manager_in_place_rule_update.cmake
)

add_test(
    NAME no_config_loader_public_outbound_factory_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_config_loader_public_outbound_factory_dependency.cmake
)

add_test(
    NAME no_controller_outbound_builder_runtime_factory_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_controller_outbound_builder_runtime_factory_dependency.cmake
)

add_test(
    NAME no_dynamic_inbound_users_outside_runtime_snapshot
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dynamic_inbound_users_outside_runtime_snapshot.cmake
)

add_test(
    NAME no_runtime_inbound_prepared_config_factory_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_runtime_inbound_prepared_config_factory_dependency.cmake
)

add_test(
    NAME no_worker_runtime_static_inbound_builder_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_runtime_static_inbound_builder_dependency.cmake
)

add_test(
    NAME no_worker_runtime_dns_service_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_runtime_dns_service_dependency.cmake
)

add_test(
    NAME no_outbound_prepared_config_dns_service_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_outbound_prepared_config_dns_service_dependency.cmake
)

add_test(
    NAME no_inbound_prepared_config_validator_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_inbound_prepared_config_validator_dependency.cmake
)

add_test(
    NAME no_rule_worker_public_api_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_rule_worker_public_api_dependency.cmake
)

add_test(
    NAME no_worker_public_dns_service_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_dns_service_dependency.cmake
)

add_test(
    NAME no_bootstrap_setup_public_dns_service_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_bootstrap_setup_public_dns_service_dependency.cmake
)

add_test(
    NAME no_bootstrap_public_common_umbrella_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_bootstrap_public_common_umbrella_dependency.cmake
)

add_test(
    NAME no_protocol_outbound_public_dns_service_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_protocol_outbound_public_dns_service_dependency.cmake
)

add_test(
    NAME no_inbound_manager_public_validator_storage
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_inbound_manager_public_validator_storage.cmake
)

add_test(
    NAME no_inbound_manager_public_factory_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_inbound_manager_public_factory_dependency.cmake
)

add_test(
    NAME no_outbound_manager_public_handler_storage
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_outbound_manager_public_handler_storage.cmake
)

add_test(
    NAME no_router_public_runtime_storage
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_router_public_runtime_storage.cmake
)

add_test(
    NAME no_worker_router_matcher_construction
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_router_matcher_construction.cmake
)

add_test(
    NAME no_worker_router_init_prepared_outbound_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_router_init_prepared_outbound_dependency.cmake
)

add_test(
    NAME no_worker_public_udp_worker_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_udp_worker_dependency.cmake
)

add_test(
    NAME no_worker_public_geodata_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_geodata_dependency.cmake
)

add_test(
    NAME no_worker_direct_sniff_config_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_direct_sniff_config_dependency.cmake
)

add_test(
    NAME no_worker_public_session_context_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_session_context_dependency.cmake
)

add_test(
    NAME no_worker_public_buffer_util_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_buffer_util_dependency.cmake
)

add_test(
    NAME no_worker_public_udp_reply_buffer_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_udp_reply_buffer_dependency.cmake
)

add_test(
    NAME no_worker_public_proxy_inbound_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_proxy_inbound_dependency.cmake
)

add_test(
    NAME no_worker_public_stats_storage_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_stats_storage_dependency.cmake
)

add_test(
    NAME no_worker_public_listener_config_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_listener_config_dependency.cmake
)

add_test(
    NAME no_worker_public_runtime_config_header_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_runtime_config_header_dependency.cmake
)

add_test(
    NAME no_unregister_listener_without_snapshot_cleanup
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_unregister_listener_without_snapshot_cleanup.cmake
)

add_test(
    NAME no_public_remove_listener_async_bypass
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_remove_listener_async_bypass.cmake
)

add_test(
    NAME no_session_tracking_full_session_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_session_tracking_full_session_dependency.cmake
)

add_test(
    NAME no_dispatcher_public_rule_manager_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_dispatcher_public_rule_manager_dependency.cmake
)

add_test(
    NAME no_outbound_manager_public_handler_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_outbound_manager_public_handler_dependency.cmake
)

add_test(
    NAME no_inbound_manager_public_handler_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_inbound_manager_public_handler_dependency.cmake
)

add_test(
    NAME no_public_online_device_tracker_type_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_online_device_tracker_type_dependency.cmake
)

add_test(
    NAME no_public_inbound_rate_limiter_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_inbound_rate_limiter_dependency.cmake
)

add_test(
    NAME no_worker_public_unused_deque_include
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_unused_deque_include.cmake
)

add_test(
    NAME no_worker_public_rule_manager_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_rule_manager_dependency.cmake
)

add_test(
    NAME no_worker_public_router_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_router_dependency.cmake
)

add_test(
    NAME no_worker_public_proxyman_manager_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_proxyman_manager_dependency.cmake
)

add_test(
    NAME no_worker_public_udp_session_manager_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_udp_session_manager_dependency.cmake
)

add_test(
    NAME no_worker_public_dispatcher_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_dispatcher_dependency.cmake
)

add_test(
    NAME no_public_session_tracking_storage_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_session_tracking_storage_dependency.cmake
)

add_test(
    NAME no_worker_public_listener_storage_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_listener_storage_dependency.cmake
)

add_test(
    NAME no_worker_public_common_umbrella_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_common_umbrella_dependency.cmake
)

add_test(
    NAME no_worker_public_private_transport_coroutines
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_private_transport_coroutines.cmake
)

add_test(
    NAME no_worker_public_listener_lifecycle_methods
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_listener_lifecycle_methods.cmake
)

add_test(
    NAME no_worker_public_runtime_state_storage
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_runtime_state_storage.cmake
)

add_test(
    NAME no_worker_public_io_context_escape
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_worker_public_io_context_escape.cmake
)

add_test(
    NAME no_controller_public_sync_state_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_controller_public_sync_state_dependency.cmake
)

add_test(
    NAME no_panel_api_public_common_umbrella_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_panel_api_public_common_umbrella_dependency.cmake
)

add_test(
    NAME no_legacy_panel_layout
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_legacy_panel_layout.cmake
)

add_test(
    NAME no_legacy_panel_models
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_legacy_panel_models.cmake
)

add_test(
    NAME no_legacy_v2board_client_names
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_legacy_v2board_client_names.cmake
)

add_test(
    NAME no_legacy_v2board_private_config
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_legacy_v2board_private_config.cmake
)

add_test(
    NAME no_v2board_public_http_helpers
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_v2board_public_http_helpers.cmake
)

add_test(
    NAME no_public_v2board_client_boundary
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_public_v2board_client_boundary.cmake
)

add_test(
    NAME no_panel_client_hot_path_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_panel_client_hot_path_dependency.cmake
)

add_test(
    NAME no_deployment_legacy_config_layout
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_deployment_legacy_config_layout.cmake
)

add_test(
    NAME no_stats_traffic_cross_layer_dependency
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_stats_traffic_cross_layer_dependency.cmake
)

add_test(
    NAME no_final_legacy_public_artifacts
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_final_legacy_public_artifacts.cmake
)

add_test(
    NAME no_final_wrapper_cross_layer_regression
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/no_final_wrapper_cross_layer_regression.cmake
)

add_test(
    NAME anytls_outbound_wire_format
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/anytls_outbound_wire_format.cmake
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
message(STATUS "  Crypto:       OpenSSL (vcpkg)")
if(WIN32)
    message(STATUS "  I/O Backend:  IOCP")
else()
    message(STATUS "  I/O Backend:  epoll")
endif()
if(HAS_MIMALLOC)
    message(STATUS "  Allocator:    mimalloc ${mimalloc_VERSION}")
else()
    message(STATUS "  Allocator:    system")
endif()
message(STATUS "  MemoryStats:  ${CNODE_MEMORY_STATS}")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION OR CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE)
    message(STATUS "  LTO:          enabled")
else()
    message(STATUS "  LTO:          disabled")
endif()
if(SANITIZER)
    message(STATUS "  Sanitizer:    ${SANITIZER}")
else()
    message(STATUS "  Sanitizer:    disabled")
endif()
message(STATUS "")
