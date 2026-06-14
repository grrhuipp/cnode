file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "std::shared_ptr[ \t\r\n]*<[ \t\r\n]*const[ \t\r\n]+WorkerRuntimeConfig[ \t\r\n]*>[ \t\r\n]+runtime_snapshot_")
    message(FATAL_ERROR
        "Worker runtime snapshot must be atomically replaceable; use atomic shared_ptr storage")
endif()

if(worker_header MATCHES "runtime_snapshot")
    message(FATAL_ERROR
        "worker.hpp must not expose runtime snapshot storage; keep it behind RuntimeState")
endif()

if(NOT worker_cpp MATCHES "std::atomic[ \t\r\n]*<[ \t\r\n]*std::shared_ptr[ \t\r\n]*<[ \t\r\n]*const[ \t\r\n]+WorkerRuntimeConfig[ \t\r\n]*>[ \t\r\n]*>[ \t\r\n]+runtime_snapshot")
    message(FATAL_ERROR
        "Worker RuntimeState must hold its current runtime snapshot in std::atomic<std::shared_ptr<const WorkerRuntimeConfig>>")
endif()
