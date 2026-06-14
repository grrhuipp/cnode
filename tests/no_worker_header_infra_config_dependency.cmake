file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)

if(worker_header MATCHES "infra/config\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must depend on a WorkerRuntimeConfig boundary, not the full infra Config header")
endif()

if(worker_header MATCHES "struct[ \t\r\n]+WorkerRuntimeConfig[ \t\r\n]*\\{")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must live outside worker.hpp so the Worker public API stays runtime-snapshot oriented")
endif()

if(NOT worker_header MATCHES "struct[ \t\r\n]+WorkerRuntimeConfig;")
    message(FATAL_ERROR
        "worker.hpp should only forward declare WorkerRuntimeConfig at the runtime snapshot boundary")
endif()
