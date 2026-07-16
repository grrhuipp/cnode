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

set(MUX_RELAY "${SOURCE_DIR}/src/common/mux/mux_relay.cpp")
file(READ "${MUX_RELAY}" MUX_RELAY_SOURCE)
if(NOT MUX_RELAY_SOURCE MATCHES "class SubLoopLease final")
    message(FATAL_ERROR
        "Mux detached sub-dispatch lifetime must be owned by its coroutine frame")
endif()
string(REGEX MATCHALL "SubLoopLease[{]reply_queue[}]"
    MUX_SUB_LOOP_LEASES "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_SUB_LOOP_LEASES MUX_SUB_LOOP_LEASE_COUNT)
if(NOT MUX_SUB_LOOP_LEASE_COUNT EQUAL 2)
    message(FATAL_ERROR
        "every TCP and UDP Mux sub-dispatch must receive an owned loop lease")
endif()
string(REGEX MATCHALL "void MarkDispatchDone[(][)] noexcept"
    MUX_NOEXCEPT_DISPATCH_COMPLETIONS "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_NOEXCEPT_DISPATCH_COMPLETIONS
    MUX_NOEXCEPT_DISPATCH_COMPLETION_COUNT)
if(NOT MUX_NOEXCEPT_DISPATCH_COMPLETION_COUNT EQUAL 2)
    message(FATAL_ERROR
        "TCP and UDP Mux dispatch completion must not strand loop ownership")
endif()
string(REGEX MATCHALL "QueueBytesWouldExceed"
    MUX_BOUNDED_QUEUE_CHECKS "${MUX_RELAY_SOURCE}")
list(LENGTH MUX_BOUNDED_QUEUE_CHECKS MUX_BOUNDED_QUEUE_CHECK_COUNT)
if(MUX_BOUNDED_QUEUE_CHECK_COUNT LESS 7)
    message(FATAL_ERROR
        "every Mux input and reply queue must use overflow-safe byte limits")
endif()
if(NOT MUX_RELAY_SOURCE MATCHES "catch [(]const std::bad_alloc&[)]")
    message(FATAL_ERROR
        "Mux relay must enter owned async cleanup after allocation failure")
endif()

foreach(MUX_CONTROL_HEADER IN ITEMS
        "${SOURCE_DIR}/include/acppnode/app/mux_session_handler.hpp"
        "${SOURCE_DIR}/include/acppnode/common/mux/mux_relay.hpp")
    file(READ "${MUX_CONTROL_HEADER}" MUX_CONTROL_HEADER_SOURCE)
    if(MUX_CONTROL_HEADER_SOURCE MATCHES "AsyncStream[*]")
        message(FATAL_ERROR
            "Mux relay control stream must be a required non-null reference: ${MUX_CONTROL_HEADER}")
    endif()
endforeach()

set(DEFAULT_DISPATCHER
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp")
file(READ "${DEFAULT_DISPATCHER}" DEFAULT_DISPATCHER_SOURCE)
if(NOT DEFAULT_DISPATCHER_SOURCE MATCHES
        "if [(]!inbound_control[)]")
    message(FATAL_ERROR
        "Dispatcher must reject Mux links without a cancellable control stream")
endif()

set(VLESS_OUTBOUND
    "${SOURCE_DIR}/src/proxy/vless/outbound/vless_outbound.cpp")
file(READ "${VLESS_OUTBOUND}" VLESS_OUTBOUND_SOURCE)
if(VLESS_OUTBOUND_SOURCE MATCHES
        "[+]\+pending_offset_[;]")
    message(FATAL_ERROR
        "VLESS outbound must not scan through invalid Mux frame bytes")
endif()
if(NOT VLESS_OUTBOUND_SOURCE MATCHES
        "frame[.]header[.]session_id != session_id_")
    message(FATAL_ERROR
        "VLESS Mux UDP responses must remain bound to their logical session")
endif()
