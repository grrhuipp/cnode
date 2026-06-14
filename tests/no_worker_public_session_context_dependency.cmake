file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)

if(worker_header MATCHES "common/session\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not expose session context internals; session::Context belongs to worker.cpp connection handling")
endif()

if(NOT worker_source MATCHES "common/session\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include common/session.hpp directly when it owns session::Context creation")
endif()
