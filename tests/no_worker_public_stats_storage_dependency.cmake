file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_stats.hpp" worker_stats_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "app/stats\\.hpp"
    "app/dns/stats\\.hpp"
    "struct[ \t\r\n]+MemoryStats"
    "struct[ \t\r\n]+RuntimeStatsSnapshot")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not define or include stats snapshot storage detail: ${pattern}")
    endif()
endforeach()

if(NOT worker_header MATCHES "struct[ \t\r\n]+StatsShard;" OR
   NOT worker_header MATCHES "using[ \t\r\n]+MemoryStats[ \t\r\n]*=[ \t\r\n]*WorkerMemoryStats" OR
   NOT worker_header MATCHES "using[ \t\r\n]+RuntimeStatsSnapshot[ \t\r\n]*=[ \t\r\n]*WorkerRuntimeStatsSnapshot")
    message(FATAL_ERROR
        "worker.hpp should keep stats dependencies behind forward declarations and compatibility aliases")
endif()

if(NOT worker_stats_header MATCHES "app/stats\\.hpp" OR
   NOT worker_stats_header MATCHES "app/dns/stats\\.hpp" OR
   NOT worker_stats_header MATCHES "struct[ \t\r\n]+WorkerMemoryStats" OR
   NOT worker_stats_header MATCHES "struct[ \t\r\n]+WorkerRuntimeStatsSnapshot")
    message(FATAL_ERROR
        "worker_stats.hpp must own Worker stats DTO definitions and their narrow stats dependencies")
endif()

if(NOT worker_cpp MATCHES "app/worker_stats\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include worker_stats.hpp where Worker stats snapshots are populated")
endif()
