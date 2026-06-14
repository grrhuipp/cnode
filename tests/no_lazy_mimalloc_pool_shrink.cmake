file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/allocator.hpp" allocator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_monitor.cpp" monitor_source)

if(NOT allocator_header MATCHES "kMimallocPurgeDelayMs[ \t\r\n]*=[ \t\r\n]*50")
    message(FATAL_ERROR "mimalloc purge delay must stay aggressive for RSS shrink")
endif()

if(NOT allocator_header MATCHES "kMimallocMinimalPurgeSizeKiB[ \t\r\n]*=[ \t\r\n]*16")
    message(FATAL_ERROR "mimalloc minimal purge size must stay small for RSS shrink")
endif()

if(NOT monitor_source MATCHES "kSteadyCollectMinConns[ \t\r\n]*=[ \t\r\n]*512")
    message(FATAL_ERROR "steady mimalloc collection must start at moderate connection counts")
endif()

if(NOT monitor_source MATCHES "kSteadyCollectInterval[ \t\r\n]*=[ \t\r\n]*std::chrono::seconds\\(2\\)")
    message(FATAL_ERROR "steady mimalloc collection interval must stay aggressive")
endif()

if(NOT monitor_source MATCHES "kRssGuardForceCollectInterval[ \t\r\n]*=[ \t\r\n]*std::chrono::seconds\\(3\\)")
    message(FATAL_ERROR "RSS guard force collection interval must stay aggressive")
endif()
