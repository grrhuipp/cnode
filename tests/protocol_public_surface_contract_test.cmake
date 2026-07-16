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

set(TRANSPORT_STACK
    "${SOURCE_DIR}/src/transport/internet/transport_stack.cpp")
file(READ "${TRANSPORT_STACK}" TRANSPORT_STACK_SOURCE)
if(NOT TRANSPORT_STACK_SOURCE MATCHES "StreamRemovalGuard")
    message(FATAL_ERROR
        "detached HTTP/2 server stream close must own exception-safe removal")
endif()
string(FIND "${TRANSPORT_STACK_SOURCE}"
    "~StreamRemovalGuard() noexcept" STREAM_REMOVAL_GUARD_DESTRUCTOR)
if(STREAM_REMOVAL_GUARD_DESTRUCTOR EQUAL -1)
    message(FATAL_ERROR
        "HTTP/2 server stream removal must run while unwinding failed writes")
endif()
