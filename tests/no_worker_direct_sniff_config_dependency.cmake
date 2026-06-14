file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)

if(worker_header MATCHES "proxy/sniff_config\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not directly include sniff config; sniffing belongs to inbound receiver/prepared config boundaries")
endif()
