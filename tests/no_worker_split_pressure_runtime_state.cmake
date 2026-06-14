file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" runtime_header)

if(worker_header MATCHES "pressure_threshold_" OR
   worker_header MATCHES "pressure_idle_timeout_")
    message(FATAL_ERROR
        "Worker must not split pressure runtime state out of the snapshot; keep derived runtime settings in WorkerRuntimeConfig")
endif()

if(NOT runtime_header MATCHES "pressure_threshold" OR
   NOT runtime_header MATCHES "pressure_idle_timeout")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must carry prepared pressure runtime settings")
endif()
