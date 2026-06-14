file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/memory_stats.hpp" stats_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_monitor.cpp" monitor_source)

if(stats_header MATCHES "g_buffers_live\\.fetch_add" OR
   stats_header MATCHES "g_buffers_live\\.fetch_sub")
    message(FATAL_ERROR "relay Buffer allocation hooks must not use hot-path atomics in production")
endif()

if(monitor_source MATCHES "mem-live: buffer=")
    message(FATAL_ERROR "runtime memory log must not report disabled Buffer counters as live data")
endif()
