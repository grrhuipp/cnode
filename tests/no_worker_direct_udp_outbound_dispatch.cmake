file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

set(forbidden_patterns
    "dispatcher_\\.Route\\("
    "outbound_handler->DispatchUDP\\("
    "dispatch\\.handler"
)

foreach(pattern IN LISTS forbidden_patterns)
    if(worker_cpp MATCHES "${pattern}")
        message(FATAL_ERROR
            "Worker must not route directly to UDP outbound; matched '${pattern}'")
    endif()
endforeach()
