file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "common/buf/multi_buffer\\.hpp"
    "buf::MultiBuffer"
    "buf::BufferGuard"
    "std::span"
    "EnqueueUdpReply"
    "StartUdpReplySend"
    "FindUdpWorkerBySocketKey")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not expose UDP reply buffer/queue implementation detail: ${pattern}")
    endif()
endforeach()

if(NOT worker_cpp MATCHES "common/buf/multi_buffer\\.hpp" OR
   NOT worker_cpp MATCHES "Worker::ListenerState::EnqueueUdpReply" OR
   NOT worker_cpp MATCHES "Worker::ListenerState::StartUdpReplySend" OR
   NOT worker_cpp MATCHES "Worker::ListenerState::FindUdpWorkerBySocketKey")
    message(FATAL_ERROR
        "worker.cpp must privately own UDP reply buffer queue operations behind Worker::ListenerState")
endif()
