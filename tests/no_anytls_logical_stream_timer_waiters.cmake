file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp" inbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp" outbound_source)

if(NOT inbound_source MATCHES "struct[ \t\r\n]+InputWaiter")
    message(FATAL_ERROR "AnyTLS inbound sub-stream reads must use a lightweight waiter")
endif()

if(NOT inbound_source MATCHES "std::coroutine_handle<>[ \t\r\n]+input_waiter_")
    message(FATAL_ERROR "AnyTLS inbound sub-stream reads must not keep a per-sub-stream timer")
endif()

if(inbound_source MATCHES "net::steady_timer[ \t\r\n]+input_timer_")
    message(FATAL_ERROR "AnyTLS inbound sub-stream must not keep a per-sub-stream steady_timer")
endif()

if(inbound_source MATCHES "input_timer_\\.expires_after\\(std::chrono::hours\\(24\\)\\)")
    message(FATAL_ERROR "AnyTLS inbound sub-stream queue waits must not be implemented as long timers")
endif()

if(NOT outbound_source MATCHES "struct[ \t\r\n]+PayloadWaiter")
    message(FATAL_ERROR "AnyTLS outbound logical stream reads must use a lightweight waiter")
endif()

if(NOT outbound_source MATCHES "std::coroutine_handle<>[ \t\r\n]+payload_waiter_")
    message(FATAL_ERROR "AnyTLS outbound logical stream reads must not keep a per-logical-stream timer")
endif()

if(outbound_source MATCHES "net::steady_timer[ \t\r\n]+timer_")
    message(FATAL_ERROR "AnyTLS outbound logical stream must not keep a per-logical-stream steady_timer")
endif()

if(outbound_source MATCHES "timer_\\.expires_after\\(std::chrono::hours\\(24\\)\\)")
    message(FATAL_ERROR "AnyTLS outbound logical stream queue waits must not be implemented as long timers")
endif()

if(NOT outbound_source MATCHES "std::unique_ptr<net::steady_timer>[ \t\r\n]+syn_timer_")
    message(FATAL_ERROR "AnyTLS outbound must keep SYN-ACK timeout as a short-lived timer")
endif()
