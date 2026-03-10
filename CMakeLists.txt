cmake_minimum_required(VERSION 3.20)

# CMP0167: CMake 4.x 移除了旧的 FindBoost 模块，使用 Boost 自带的 CMake 配置文件
cmake_policy(SET CMP0167 NEW)

# 抑制第三方依赖（如 aws-lc）的 cmake_minimum_required 过旧警告
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

# ============================================================================
# C++ 标准与编译选项
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 编译选项：使用 generator expression 区分编译器，避免污染 FetchContent 子项目
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

# Boost (需要 1.90+，支持 C++20 协程 + Boost.Cobalt + Boost.JSON)（via vcpkg）
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
find_package(Boost 1.90 REQUIRED COMPONENTS cobalt log)
if(Boost_FOUND)
    message(STATUS "Found Boost ${Boost_VERSION}")
endif()

# Threads
find_package(Threads REQUIRED)

# AWS-LC（替代 OpenSSL，性能更优的密码学库）
include(FetchContent)
set(AWS_LC_VERSION "v1.69.0" CACHE STRING "AWS-LC version tag")
FetchContent_Declare(
    aws_lc
    GIT_REPOSITORY https://github.com/aws/aws-lc.git
    GIT_TAG        ${AWS_LC_VERSION}
    GIT_SHALLOW    TRUE
)
# AWS-LC 构建选项：只构建静态库，禁用测试和工具
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_TOOL OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(DISABLE_PERL ON CACHE BOOL "" FORCE)
set(DISABLE_GO ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(aws_lc)
message(STATUS "Using AWS-LC (crypto library)")

# zlib (用于 CRC32)（via vcpkg）
find_package(ZLIB REQUIRED)

# ============================================================================
# mimalloc 高性能内存分配器（via vcpkg）
# 注意：mimalloc 与 ASan/MSan/TSan 不兼容，启用 Sanitizer 时自动禁用
# ============================================================================
option(USE_MIMALLOC "Use mimalloc as default memory allocator" ON)

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

    # Infra (logging, config)
    src/infra/log.cpp
    src/infra/config.cpp
    
    # DNS
    src/dns/dns_service.cpp
    src/dns/dns_cache.cpp
    
    # Geo
    src/geo/geodata.cpp
    
    # Transport
    src/transport/async_stream.cpp
    src/transport/tcp_stream.cpp
    src/transport/timeout_scheduler.cpp
    src/transport/tls_stream.cpp
    src/transport/ws_stream.cpp
    src/transport/transport_stack.cpp
    src/transport/transport_dialer.cpp
    src/transport/proxy_protocol.cpp

    # App (Application layer)
    src/app/session_handler.cpp
    src/app/worker.cpp
    src/app/panel_sync.cpp
    src/app/relay_tcp.cpp        # DoRelay, DoRelayWithFirstPacket (TCP)
    src/app/relay_udp.cpp        # DoUDPRelay (UDP)
    src/app/mux_relay.cpp
    src/app/session_context.cpp
    src/app/stats.cpp
    src/app/udp_session.cpp
    
    # Sniff
    src/sniff/sniffer.cpp
    src/sniff/tls_sniffer.cpp
    src/sniff/http_sniffer.cpp
    
    # Protocol - Mux
    src/protocol/mux/mux_codec.cpp

    # Protocol - VMess
    src/protocol/vmess/vmess_protocol.cpp
    src/protocol/vmess/vmess_stream.cpp
    src/protocol/vmess/inbound/vmess_inbound.cpp
    src/protocol/vmess/outbound/vmess_outbound.cpp

    # Protocol - Trojan
    src/protocol/trojan/trojan_user_manager.cpp
    src/protocol/trojan/trojan_codec.cpp
    src/protocol/trojan/trojan_protocol.cpp
    src/protocol/trojan/inbound/trojan_inbound.cpp
    src/protocol/trojan/outbound/trojan_outbound.cpp

    # Protocol - Shadowsocks
    src/protocol/shadowsocks/shadowsocks_protocol.cpp
    src/protocol/shadowsocks/ss_udp.cpp
    src/protocol/shadowsocks/ss_udp_inbound.cpp
    src/protocol/shadowsocks/inbound/ss_inbound.cpp
    src/protocol/shadowsocks/outbound/ss_outbound.cpp

    # Protocol - Freedom
    src/protocol/freedom/freedom_outbound.cpp

    # Protocol - Blackhole
    src/protocol/blackhole/blackhole_outbound.cpp

    # Protocol - Registry（出站/入站自注册中心）
    src/protocol/protocol_registry.cpp
    src/protocol/inbound_registry.cpp
    
    # Router
    src/router/router.cpp
    
    # Panel
    src/panel/v2board_panel.cpp
    
    # Main
    src/main.cpp
)

# ============================================================================
# 可执行文件
# ============================================================================
add_executable(cnode ${CNODE_SOURCES})

target_include_directories(cnode BEFORE PRIVATE
    ${aws_lc_SOURCE_DIR}/include
)
target_include_directories(cnode PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(cnode PRIVATE
    Boost::cobalt
    Boost::log
    Threads::Threads
    ssl
    crypto
    ZLIB::ZLIB
)

# 构建版本号：优先使用外部传入的 BUILD_ID，否则生成随机 hex
if(NOT DEFINED BUILD_ID OR BUILD_ID STREQUAL "")
    string(RANDOM LENGTH 12 ALPHABET "0123456789abcdef" BUILD_ID)
endif()
target_compile_definitions(cnode PRIVATE BUILD_ID="${BUILD_ID}")
message(STATUS "Build ID: ${BUILD_ID}")

# 条件链接 mimalloc（必须早于其他库以覆盖 malloc/new）
if(HAS_MIMALLOC)
    target_link_libraries(cnode PRIVATE mimalloc-static)
    target_compile_definitions(cnode PRIVATE USE_MIMALLOC)
    message(STATUS "Linking mimalloc-static for malloc override")
endif()

# 预编译头（PCH）- 加速 Boost/OpenSSL/标准库模板的编译
target_precompile_headers(cnode PRIVATE src/pch.hpp)

# 为我们自己的代码添加警告（不影响 FetchContent 子项目）
target_compile_options(cnode PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4100 /wd4324 /EHsc /Zc:preprocessor /bigobj>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wno-unused-parameter -Wpedantic -Wno-mismatched-new-delete -Wno-stringop-overread -Wno-free-nonheap-object>
)
# LTO 链接阶段同样禁用 Boost.JSON 误报警告
target_link_options(cnode PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-stringop-overread -Wno-free-nonheap-object>
)

# 平台链接库
if(WIN32)
    target_link_libraries(cnode PRIVATE ws2_32 mswsock psapi)
elseif(UNIX AND NOT APPLE)
    # Linux: 静态链接时需要显式链接 pthread/dl/rt
    target_link_libraries(cnode PRIVATE dl rt)
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
message(STATUS "  Boost:        ${Boost_VERSION}")
message(STATUS "  Crypto:       AWS-LC")
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
