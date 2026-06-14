file(READ "${PROJECT_SOURCE_DIR}/CMakeLists.txt" cmake_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_monitor.cpp" monitor_source)

if(NOT cmake_source MATCHES "option\\(CNODE_MEMORY_STATS[^\n]*ON\\)")
    message(FATAL_ERROR "runtime memory stats must be enabled in release builds during RSS tuning")
endif()

if(NOT monitor_source MATCHES "mem-live: buffer=\\{\\}/\\{\\} .*tls_stream=\\{\\}/\\{\\}")
    message(FATAL_ERROR "runtime memory logs must include live/peak TLS stream counters")
endif()
