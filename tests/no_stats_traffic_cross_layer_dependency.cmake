file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/traffic_types.hpp" traffic_types_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/session_tracking.hpp" session_tracking_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_stats.hpp" worker_stats_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/api/api.hpp" panel_api_header)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_control)

if(NOT traffic_types_header MATCHES "struct[ \t\r\n]+UserTraffic" OR
   NOT traffic_types_header MATCHES "struct[ \t\r\n]+UserTrafficSnapshot" OR
   NOT traffic_types_header MATCHES "std::unordered_map<int64_t,[ \t\r\n]*UserTraffic>")
    message(FATAL_ERROR "app/traffic_types.hpp must own the app-layer user traffic DTO boundary")
endif()

if(NOT session_tracking_header MATCHES "app/traffic_types\\.hpp" OR
   NOT session_tracking_header MATCHES "class[ \t\r\n]+SessionTrackingState" OR
   NOT session_tracking_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT session_tracking_header MATCHES "std::unique_ptr<Impl>" OR
   NOT session_tracking_header MATCHES "CollectAndResetTraffic")
    message(FATAL_ERROR "session_tracking.hpp must expose only a PImpl traffic collection boundary")
endif()

foreach(pattern IN ITEMS
    "std::unordered_map"
    "LocalTrafficStore"
    "ActiveSessionMap"
    "ThreadLocal"
    "common/session\\.hpp"
    "common/allocator")
    if(session_tracking_header MATCHES "${pattern}")
        message(FATAL_ERROR "session_tracking.hpp must not expose traffic storage detail: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "app/traffic_types\\.hpp"
    "app/stats\\.hpp"
    "app/dns/stats\\.hpp"
    "app/session_tracking\\.hpp")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR "worker.hpp must keep stats/traffic dependencies behind forward declarations: ${pattern}")
    endif()
endforeach()

if(NOT worker_stats_header MATCHES "app/stats\\.hpp" OR
   NOT worker_stats_header MATCHES "app/dns/stats\\.hpp" OR
   NOT worker_stats_header MATCHES "struct[ \t\r\n]+WorkerRuntimeStatsSnapshot")
    message(FATAL_ERROR "worker_stats.hpp must own the Worker runtime stats DTO boundary")
endif()

foreach(pattern IN ITEMS
    "app/traffic_types\\.hpp"
    "app/stats\\.hpp"
    "app/session_tracking\\.hpp"
    "app/worker\\.hpp"
    "app/proxyman/")
    if(panel_api_header MATCHES "${pattern}")
        message(FATAL_ERROR "Panel API public header must not depend on app stats/traffic hot-path types: ${pattern}")
    endif()
endforeach()

file(GLOB_RECURSE panel_client_files
    "${PROJECT_SOURCE_DIR}/src/api/*.hpp"
    "${PROJECT_SOURCE_DIR}/src/api/*.cpp"
)
foreach(file IN LISTS panel_client_files)
    file(READ "${file}" content)
    foreach(pattern IN ITEMS
        "app/traffic_types\\.hpp"
        "app/stats\\.hpp"
        "app/session_tracking\\.hpp"
        "app/worker\\.hpp"
        "app/proxyman/")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Panel client implementation must not depend on app stats/traffic hot-path types: ${file} matches ${pattern}")
        endif()
    endforeach()
endforeach()

if(NOT controller_control MATCHES "Worker::UserTrafficSnapshot" OR
   NOT controller_control MATCHES "std::unordered_map<int64_t,[ \t\r\n]*api::UserTraffic>" OR
   NOT controller_control MATCHES "GetTrafficTask" OR
   NOT controller_control MATCHES "ReportUserTraffic")
    message(FATAL_ERROR "Controller control plane must own Worker traffic collection and api::UserTraffic reporting translation")
endif()
