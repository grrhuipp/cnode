file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)

if(worker_header MATCHES "GetIoContext")
    message(FATAL_ERROR
        "worker.hpp must not expose the mutable io_context; external code should use GetExecutor for cross-thread posting")
endif()

if(worker_header MATCHES "net::io_context&[ \t\r\n]+Get")
    message(FATAL_ERROR
        "worker.hpp must not expose net::io_context& accessors")
endif()

if(NOT worker_header MATCHES "GetExecutor")
    message(FATAL_ERROR
        "Worker should expose an executor boundary for controller/monitor collection tasks")
endif()
