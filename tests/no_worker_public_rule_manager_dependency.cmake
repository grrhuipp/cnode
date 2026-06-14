file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "common/rule\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the full rule manager implementation header")
endif()

if(worker_header MATCHES "rule::Manager[ \t\r\n]+rule_manager_")
    message(FATAL_ERROR
        "Worker public header must not store rule::Manager by value; keep detect runtime storage behind an implementation pointer")
endif()

if(worker_header MATCHES "rule_manager_")
    message(FATAL_ERROR
        "worker.hpp must not expose the rule manager member; keep it behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold runtime implementation details through an opaque RuntimeState pointer")
endif()

if(NOT worker_cpp MATCHES "common/rule\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include common/rule.hpp privately when it creates or calls rule::Manager")
endif()

if(NOT worker_cpp MATCHES "std::make_unique<rule::Manager>")
    message(FATAL_ERROR
        "Worker implementation must construct the private rule::Manager instance")
endif()
