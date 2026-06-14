file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "app/dispatcher/default_dispatcher\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the concrete DefaultDispatcher implementation boundary")
endif()

if(worker_header MATCHES "app::dispatcher::DefaultDispatcher[ \t\r\n]+dispatcher_")
    message(FATAL_ERROR
        "Worker public header must not store DefaultDispatcher by value")
endif()

if(worker_header MATCHES "dispatcher_")
    message(FATAL_ERROR
        "worker.hpp must not expose the dispatcher member; keep it behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold runtime implementation details through an opaque RuntimeState pointer")
endif()

if(NOT worker_cpp MATCHES "app/dispatcher/default_dispatcher\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include default_dispatcher.hpp privately")
endif()

if(NOT worker_cpp MATCHES "std::make_unique<app::dispatcher::DefaultDispatcher>")
    message(FATAL_ERROR
        "Worker implementation must construct the private DefaultDispatcher instance")
endif()
