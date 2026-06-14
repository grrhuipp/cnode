file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/allocator.hpp" allocator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_monitor.cpp" monitor_source)

if(NOT allocator_header MATCHES "kMimallocPurgeDelayMs[ \t\r\n]*=[ \t\r\n]*50")
    message(FATAL_ERROR "mimalloc purge delay must stay aggressive for RSS shrink")
endif()

if(NOT allocator_header MATCHES "kMimallocMinimalPurgeSizeKiB[ \t\r\n]*=[ \t\r\n]*16")
    message(FATAL_ERROR "mimalloc minimal purge size must stay small for RSS shrink")
endif()

if(NOT allocator_header MATCHES "PR_SET_THP_DISABLE")
    message(FATAL_ERROR "process-level THP must stay disabled to avoid RSS amplification under churn")
endif()

if(NOT monitor_source MATCHES "kSteadyCollectMinConns[ \t\r\n]*=[ \t\r\n]*512")
    message(FATAL_ERROR "steady mimalloc collection must start at moderate connection counts")
endif()

if(NOT monitor_source MATCHES "kSteadyCollectInterval[ \t\r\n]*=[ \t\r\n]*std::chrono::seconds\\(10\\)")
    message(FATAL_ERROR "steady mimalloc collection interval must stay frequent without becoming a CPU tax")
endif()

if(NOT monitor_source MATCHES "kChurnForceCollectConnections[ \t\r\n]*=[ \t\r\n]*2048")
    message(FATAL_ERROR "churn-driven full collection must react to sustained connection turnover")
endif()

if(NOT monitor_source MATCHES "kChurnForceCollectCooldown[ \t\r\n]*=[ \t\r\n]*std::chrono::seconds\\(60\\)")
    message(FATAL_ERROR "churn-driven full collection must stay low-frequency to avoid a CPU tax")
endif()

if(NOT monitor_source MATCHES "mem-collect force reason=")
    message(FATAL_ERROR "force collection must be observable in production logs")
endif()

if(monitor_source MATCHES "kTargetRssPerConnBytes|rss_guard_collect_due|rss_per_conn_over_target")
    message(FATAL_ERROR "runtime monitor must not force-collect from total RSS/active connection ratio")
endif()

if(NOT monitor_source MATCHES "burst_drain[ \t\r\n\\|\\(\\)]*\\|\\|[ \t\r\n\\|\\(\\)]*newly_idle")
    message(FATAL_ERROR "mimalloc force collection must still run when connection bursts drain or become idle")
endif()

if(NOT monitor_source MATCHES "churn_collect_due")
    message(FATAL_ERROR "mimalloc force collection must also handle sustained connection churn")
endif()
