if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/include/acppnode/app/bootstrap_runtime.hpp"
    RUNTIME_HEADER)
file(READ
    "${SOURCE_DIR}/include/acppnode/app/bootstrap_monitor.hpp"
    MONITOR_HEADER)
file(READ
    "${SOURCE_DIR}/src/app/bootstrap_monitor.cpp"
    MONITOR_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/bootstrap_shutdown.cpp"
    SHUTDOWN_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/bootstrap_runtime.cpp"
    RUNTIME_SOURCE)

if(RUNTIME_HEADER MATCHES "RuntimeState" OR
   MONITOR_HEADER MATCHES "StartRuntimeMonitoring")
    message(FATAL_ERROR
        "runtime monitoring must not borrow stack state through detached entrypoints")
endif()

foreach(REQUIRED_MONITOR
        "class RuntimeMonitor"
        "net::awaitable<void> Stop();"
        "std::shared_ptr<Impl> impl_;")
    string(FIND "${MONITOR_HEADER}" "${REQUIRED_MONITOR}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "RuntimeMonitor boundary is missing '${REQUIRED_MONITOR}'")
    endif()
endforeach()

foreach(REQUIRED_IMPLEMENTATION
        "RunOwned(shared_from_this())"
        "state.timers.CancelAll()"
        "co_await completion.async_wait")
    string(FIND "${MONITOR_SOURCE}"
        "${REQUIRED_IMPLEMENTATION}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "RuntimeMonitor ownership is missing '${REQUIRED_IMPLEMENTATION}'")
    endif()
endforeach()

string(REGEX MATCHALL "RunAwaitableBatch" BATCH_CALLS "${MONITOR_SOURCE}")
list(LENGTH BATCH_CALLS BATCH_CALL_COUNT)
if(BATCH_CALL_COUNT LESS 3)
    message(FATAL_ERROR
        "Worker sampling, heap collection, and monitor loops must share the batch primitive")
endif()

string(FIND "${SHUTDOWN_SOURCE}" "std::_Exit(EXIT_SUCCESS)" FORCE_EXIT)
if(FORCE_EXIT EQUAL -1 OR
   NOT SHUTDOWN_SOURCE MATCHES "status=forced")
    message(FATAL_ERROR
        "signal shutdown must terminate immediately without runtime teardown")
endif()

if(SHUTDOWN_SOURCE MATCHES "monitor.Stop\\(\\)" OR
   SHUTDOWN_SOURCE MATCHES "controller.Stop\\(\\)" OR
   SHUTDOWN_SOURCE MATCHES "ShutdownWorkers")
    message(FATAL_ERROR
        "signal shutdown must not enter monitor, controller, or Worker teardown")
endif()

if(RUNTIME_SOURCE MATCHES "run_for\\(" OR
   RUNTIME_SOURCE MATCHES "milliseconds\\(100\\)")
    message(FATAL_ERROR
        "runtime shutdown must not depend on a fixed drain window")
endif()
