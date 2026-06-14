file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" worker_runtime_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/dns/dns.hpp" dns_header)

if(worker_runtime_config MATCHES "app/dns/dns\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must depend on DNS runtime config data, not the full DNS service implementation header")
endif()

if(NOT worker_runtime_config MATCHES "app/dns/config\\.hpp")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must include the DNS runtime config boundary")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/app/dns/config.hpp")
    message(FATAL_ERROR
        "app/dns/config.hpp must exist as the narrow DNS runtime config boundary")
endif()

if(NOT dns_header MATCHES "app/dns/config\\.hpp")
    message(FATAL_ERROR
        "DNS service header must include the DNS runtime config boundary")
endif()
