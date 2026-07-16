if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/include/acppnode/service/controller/controller.hpp"
    CONTROLLER_HEADER)
file(READ
    "${SOURCE_DIR}/src/service/controller/controller.cpp"
    CONTROLLER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/bootstrap_shutdown.cpp"
    SHUTDOWN_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/api/api.hpp"
    API_HEADER)
file(READ
    "${SOURCE_DIR}/src/api/v2board/v2board.cpp"
    V2BOARD_SOURCE)
file(READ
    "${SOURCE_DIR}/src/common/cancelable_timer_registry.hpp"
    TIMER_REGISTRY_HEADER)

foreach(REQUIRED_HEADER
        "net::awaitable<void> Stop();"
        "std::shared_ptr<Impl> impl_;"
        "Controller(Controller&&) = delete")
    string(FIND "${CONTROLLER_HEADER}" "${REQUIRED_HEADER}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "Controller lifetime boundary is missing '${REQUIRED_HEADER}'")
    endif()
endforeach()

foreach(REQUIRED_SOURCE
        "runPanelMonitorsOwned(shared_from_this(), generation)"
        "panel->CancelPending()"
        "monitor_timers_.CancelAll()"
        "co_await monitor_completion_.async_wait")
    string(FIND "${CONTROLLER_SOURCE}" "${REQUIRED_SOURCE}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "Controller monitor cancellation is missing '${REQUIRED_SOURCE}'")
    endif()
endforeach()

if(NOT TIMER_REGISTRY_HEADER MATCHES "class CancelableTimerRegistry" OR
   NOT TIMER_REGISTRY_HEADER MATCHES "timer->cancel\\(ignored\\)")
    message(FATAL_ERROR
        "Controller and runtime monitors must share the timer cancellation primitive")
endif()

if(NOT API_HEADER MATCHES "virtual void CancelPending\\(\\) noexcept = 0")
    message(FATAL_ERROR
        "panel API must expose native pending-I/O cancellation")
endif()
foreach(REQUIRED_CANCEL_PATH
        "void APIClient::Impl::CancelPending() noexcept"
        "socket->cancel(ignored)"
        "socket->close(ignored)"
        "request_epoch != cancel_epoch_")
    string(FIND "${V2BOARD_SOURCE}"
        "${REQUIRED_CANCEL_PATH}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "V2Board cancellation is missing '${REQUIRED_CANCEL_PATH}'")
    endif()
endforeach()

string(FIND "${SHUTDOWN_SOURCE}"
    "co_await ctx.controller.Stop()" CONTROLLER_STOP)
string(FIND "${SHUTDOWN_SOURCE}"
    "co_await ShutdownWorkers(ctx)" WORKER_STOP)
if(CONTROLLER_STOP EQUAL -1 OR WORKER_STOP EQUAL -1 OR
   NOT CONTROLLER_STOP LESS WORKER_STOP)
    message(FATAL_ERROR
        "shutdown must await Controller quiescence before stopping Workers")
endif()

if(SHUTDOWN_SOURCE MATCHES "[\r\n][ \t]+ctx.controller.Stop\\(\\);")
    message(FATAL_ERROR
        "synchronous fire-and-forget Controller stop must not return")
endif()
