file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "app/router/router\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the full Router implementation boundary")
endif()

if(worker_header MATCHES "app::router::Router[ \t\r\n]+router_")
    message(FATAL_ERROR
        "Worker public header must not store Router by value")
endif()

if(worker_header MATCHES "router_")
    message(FATAL_ERROR
        "worker.hpp must not expose the Router member; keep it behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold runtime implementation details through an opaque RuntimeState pointer")
endif()

if(NOT worker_cpp MATCHES "app/router/router\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include app/router/router.hpp privately")
endif()

if(NOT worker_cpp MATCHES "std::make_unique<app::router::Router>")
    message(FATAL_ERROR
        "Worker implementation must construct the private Router instance")
endif()
