file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "proxy/inbound\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the full proxy inbound interface; keep Inbound behind a forward declaration")
endif()

if(NOT worker_header MATCHES "class[ \t\r\n]+Inbound;")
    message(FATAL_ERROR
        "worker.hpp should forward declare Inbound for unique_ptr API boundaries")
endif()

if(NOT worker_cpp MATCHES "proxy/inbound\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include the full proxy inbound interface where Worker constructs protocol handlers")
endif()
