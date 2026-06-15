file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/allocator.hpp" allocator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_monitor.cpp" monitor_source)

if(NOT allocator_header MATCHES "kGlibcArenaMax[ \t\r\n]*=[ \t\r\n]*2")
    message(FATAL_ERROR "glibc heaptrack builds must cap malloc arenas to limit per-worker RSS retention")
endif()

if(NOT allocator_header MATCHES "M_ARENA_MAX")
    message(FATAL_ERROR "glibc allocator setup must apply M_ARENA_MAX")
endif()

if(NOT allocator_header MATCHES "M_TRIM_THRESHOLD" OR
   NOT allocator_header MATCHES "M_MMAP_THRESHOLD")
    message(FATAL_ERROR "glibc allocator setup must keep aggressive trim/mmap thresholds")
endif()

if(NOT allocator_header MATCHES "malloc_trim[ \t\r\n]*\\(")
    message(FATAL_ERROR "glibc allocator collection must call malloc_trim")
endif()

if(NOT monitor_source MATCHES "memory::kAllocatorCollects")
    message(FATAL_ERROR "runtime memory collection must run for every allocator that supports trimming")
endif()

if(monitor_source MATCHES "#ifdef[ \t]+USE_MIMALLOC")
    message(FATAL_ERROR "heap collection must not be limited to mimalloc builds")
endif()
