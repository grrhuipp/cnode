file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)

if(worker_header MATCHES "#[ \t]*include[ \t]*<deque>")
    message(FATAL_ERROR
        "worker.hpp must not expose <deque> unless Worker's public boundary directly uses std::deque")
endif()

if(worker_header MATCHES "std::deque|ThreadLocalDeque")
    message(FATAL_ERROR
        "worker.hpp should not expose deque-based storage in the public Worker boundary")
endif()
