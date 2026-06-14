file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "TimeoutsConfig[ \t\r\n]+timeouts_")
    message(FATAL_ERROR
        "Worker must not split timeout runtime state out of the snapshot; keep runtime state behind WorkerRuntimeConfig")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker must keep runtime state behind an opaque RuntimeState pointer")
endif()

if(NOT worker_cpp MATCHES "std::atomic[ \t\r\n]*<[ \t\r\n]*std::shared_ptr[ \t\r\n]*<[ \t\r\n]*const[ \t\r\n]+WorkerRuntimeConfig[ \t\r\n]*>[ \t\r\n]*>[ \t\r\n]+runtime_snapshot")
    message(FATAL_ERROR
        "Worker RuntimeState must hold a current atomic WorkerRuntimeConfig runtime snapshot")
endif()
