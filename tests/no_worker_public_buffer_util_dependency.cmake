file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)

if(worker_header MATCHES "common/buffer_util\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include buffer_util helpers; keep scratch-buffer release utilities in implementation files")
endif()

if(worker_header MATCHES "common/buf/multi_buffer\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include MultiBuffer; UDP reply queue storage belongs behind Worker listener state")
endif()
