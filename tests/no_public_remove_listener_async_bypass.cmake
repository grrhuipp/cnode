file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)

if(worker_header MATCHES "RemoveListenerAsync" OR
   worker_source MATCHES "Worker::RemoveListenerAsync")
    message(FATAL_ERROR
        "Worker must not expose RemoveListenerAsync; inbound removal must use UnregisterListenerAsync so handler state and runtime snapshot are cleaned together")
endif()

if(NOT worker_header MATCHES "UnregisterListenerAsync" OR
   NOT worker_source MATCHES "Worker::UnregisterListenerAsync")
    message(FATAL_ERROR
        "Worker must keep UnregisterListenerAsync as the public listener removal path")
endif()
