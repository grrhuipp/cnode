file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" runtime_header)

if(runtime_header MATCHES "infra/config\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must not depend on the full Config class header")
endif()

if(runtime_header MATCHES "infra/config_types\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must not depend on the full config_types collection; use the runtime config type boundary")
endif()

if(NOT runtime_header MATCHES "infra/runtime_config_types\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must include the narrow runtime config type boundary")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/infra/runtime_config_types.hpp")
    message(FATAL_ERROR
        "runtime_config_types.hpp must exist as the narrow Worker runtime config data boundary")
endif()
