file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "AcceptLoop"
    "ProcessReceivedConnection"
    "UdpReceiveLoop"
    "tcp::acceptor"
    "tcp::socket"
    "tcp::endpoint"
    "udp::socket"
    "udp::endpoint")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not expose private listener coroutine or transport socket detail: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "Worker::ListenerState::AcceptLoop"
    "Worker::ListenerState::ProcessReceivedConnection"
    "Worker::ListenerState::UdpReceiveLoop")
    if(NOT worker_cpp MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.cpp must keep private listener coroutine implementation behind ListenerState: ${pattern}")
    endif()
endforeach()
