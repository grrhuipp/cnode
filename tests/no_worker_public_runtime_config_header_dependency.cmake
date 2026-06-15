file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "app/worker_runtime_config\\.hpp"
    "app/proxyman/inbound/prepared_config\\.hpp"
    "app/proxyman/outbound/prepared_config\\.hpp"
    "app/static_inbound_prepared_config\\.hpp"
    "infra/config_types\\.hpp")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not include full runtime/prepared config headers: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "struct[ \t\r\n]+WorkerRuntimeConfig;"
    "struct[ \t\r\n]+RoutingConfig;"
    "struct[ \t\r\n]+BuildRequest;"
    "struct[ \t\r\n]+PreparedOutboundConfig;")
    if(NOT worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp should expose runtime/prepared config only through forward declarations: ${pattern}")
    endif()
endforeach()

if(worker_header MATCHES "struct[ \t\r\n]+UserSet;" OR
   worker_header MATCHES "InboundUsers")
    message(FATAL_ERROR
        "worker.hpp must not expose inbound user sets or inbound-user update APIs")
endif()

if(NOT worker_cpp MATCHES "app/worker_runtime_config\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include worker_runtime_config.hpp where Worker reads and updates runtime snapshots")
endif()
