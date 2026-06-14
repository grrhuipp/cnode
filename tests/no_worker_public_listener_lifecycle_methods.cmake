file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "void[ \t\r\n]+StartListening"
    "void[ \t\r\n]+StopListening"
    "void[ \t\r\n]+StartUdpListening"
    "void[ \t\r\n]+StopUdpListening"
    "void[ \t\r\n]+RetireInboundHandler"
    "void[ \t\r\n]+DrainRetiredListenerStateIfIdle"
    "void[ \t\r\n]+DrainRetiredHandlersIfIdle")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not expose private listener lifecycle implementation method: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "Worker::ListenerState::StartListening"
    "Worker::ListenerState::StopListening"
    "Worker::ListenerState::StartUdpListening"
    "Worker::ListenerState::StopUdpListening"
    "Worker::ListenerState::RetireInboundHandler"
    "Worker::ListenerState::DrainRetiredHandlersIfIdle")
    if(NOT worker_cpp MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.cpp must keep listener lifecycle implementation behind ListenerState: ${pattern}")
    endif()
endforeach()
