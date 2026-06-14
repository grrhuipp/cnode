file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "common/allocator\\.hpp"
    "common/string_hash\\.hpp"
    "ThreadLocalUnorderedMap"
    "ListenerSlotMap"
    "tcp_listener_tags"
    "listener_slots"
    "udp_socket_tags"
    "udp_workers")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not expose Worker listener/runtime storage detail: ${pattern}")
    endif()
endforeach()

if(worker_header MATCHES "listener_state_")
    message(FATAL_ERROR
        "worker.hpp must not expose the listener state member; keep it behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold listener state through an opaque RuntimeState pointer")
endif()

if(NOT worker_cpp MATCHES "struct[ \t\r\n]+Worker::ListenerState" OR
   NOT worker_cpp MATCHES "ThreadLocalUnorderedMap" OR
   NOT worker_cpp MATCHES "tcp_listener_tags" OR
   NOT worker_cpp MATCHES "udp_workers")
    message(FATAL_ERROR
        "worker.cpp must privately own listener maps and UDP worker runtime storage")
endif()
