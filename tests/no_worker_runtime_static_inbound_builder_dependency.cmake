file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" worker_runtime_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_runtime.hpp" static_inbound_runtime)

if(worker_runtime_config MATCHES "app/static_inbound_runtime\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must depend on the prepared static inbound entry boundary, not the cold-path static inbound builder API")
endif()

if(NOT worker_runtime_config MATCHES "app/static_inbound_prepared_config\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must include the prepared static inbound entry boundary")
endif()

if(static_inbound_runtime MATCHES "struct[ \t\r\n]+StaticInboundRuntimeEntry")
    message(FATAL_ERROR
        "StaticInboundRuntimeEntry must live in static_inbound_prepared_config.hpp so runtime snapshots do not include cold-path builder declarations")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_prepared_config.hpp")
    message(FATAL_ERROR
        "static_inbound_prepared_config.hpp must exist as the narrow runtime data boundary")
endif()
