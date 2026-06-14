file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

set(forbidden_patterns
    "#[ \t]*include[ \t]+[<\"]acppnode/app/relay\\.hpp"
    "DoRelay"
    "DoUDPRelay"
)

foreach(pattern IN LISTS forbidden_patterns)
    if(worker_cpp MATCHES "${pattern}")
        message(FATAL_ERROR "Worker must not depend on relay APIs; matched '${pattern}'")
    endif()
endforeach()
