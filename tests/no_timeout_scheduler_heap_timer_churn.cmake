file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/timeout_scheduler.cpp" scheduler_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/timeout_scheduler.hpp" scheduler_header)

if(NOT scheduler_source MATCHES "kScanInterval[ \t\r\n]*=[ \t\r\n]*std::chrono::seconds\\(1\\)" OR
   NOT scheduler_source MATCHES "timer\\.expires_after\\(kScanInterval\\)")
    message(FATAL_ERROR "TimeoutScheduler must use one fixed-tick timer per io_context shard")
endif()

if(NOT scheduler_source MATCHES "for[ \t\r\n]*\\([ \t\r\n]*auto[ \t\r\n]+it[ \t\r\n]*=[ \t\r\n]*events\\.begin\\(\\)" OR
   NOT scheduler_source MATCHES "it[ \t\r\n]*=[ \t\r\n]*events\\.erase\\(it\\)")
    message(FATAL_ERROR "TimeoutScheduler must lazily scan the event map and erase due events")
endif()

foreach(pattern IN ITEMS
    "#include[ \t]*<queue>"
    "std::priority_queue"
    "TimeoutQueueItem"
    "MaybeCompact"
    "\\.expires_at\\("
    "\\.expiry\\("
    "\\.cancel\\(")
    if(scheduler_source MATCHES "${pattern}")
        message(FATAL_ERROR "TimeoutScheduler must not use heap or dynamic timer rearm pattern: ${pattern}")
    endif()
endforeach()

if(NOT scheduler_header MATCHES "固定 tick 惰性扫描")
    message(FATAL_ERROR "TimeoutScheduler header must document fixed-tick lazy scanning")
endif()
