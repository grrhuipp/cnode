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
        "std::unique_ptr<Impl> impl_;")
    string(FIND "${MONITOR_HEADER}" "${REQUIRED_MONITOR}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "RuntimeMonitor boundary is missing '${REQUIRED_MONITOR}'")
    endif()
endforeach()

if(MONITOR_HEADER MATCHES "bootstrap_runtime.hpp|awaitable|Stop[(]" OR
   MONITOR_SOURCE MATCHES "RuntimeMonitorState|CancelableTimerRegistry|RuntimeMonitor::Stop")
    message(FATAL_ERROR
        "monitor must not restore unused stop state or expose full runtime dependencies")
endif()

string(REGEX MATCHALL "RunAwaitableBatch" BATCH_CALLS "${MONITOR_SOURCE}")
list(LENGTH BATCH_CALLS BATCH_CALL_COUNT)
if(NOT BATCH_CALL_COUNT EQUAL 2)
    message(FATAL_ERROR
        "only finite Worker sampling and heap collection may use the batch primitive; monitor loops complete independently")
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
   RUNTIME_SOURCE MATCHES "milliseconds\\(100\\)|ShutdownTask|workers.clear|ReleaseForIoContext|->stop\\(")
    message(FATAL_ERROR
        "process-lifetime runtime must not partially tear down active Worker state")
endif()

if(NOT RUNTIME_HEADER MATCHES "noreturn" OR
   NOT SHUTDOWN_SOURCE MATCHES "std::_Exit[(]EXIT_FAILURE[)]" OR
   NOT RUNTIME_SOURCE MATCHES "FailRuntime")
    message(FATAL_ERROR "runtime failure must terminate with failure status without unwinding its owners")
endif()
