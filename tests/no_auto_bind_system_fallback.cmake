file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/transport_dialer.cpp" dialer_cpp)

if(dialer_cpp MATCHES "retrying with system bind" OR
   dialer_cpp MATCHES "ShouldRetryWithoutBind")
    message(FATAL_ERROR
        "Auto sendThrough must not fall back to system bind; source-in/source-out must stay strict")
endif()
