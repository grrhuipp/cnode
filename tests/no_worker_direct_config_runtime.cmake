set(files
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp"
    "${PROJECT_SOURCE_DIR}/src/app/worker.cpp"
)

foreach(path IN LISTS files)
    file(READ "${path}" content)
    if(content MATCHES "Worker::Worker[ \t\r\n]*\\([^)]*const[ \t\r\n]+Config[ \t\r\n]*&" OR
       content MATCHES "Worker[ \t\r\n]*\\([^)]*const[ \t\r\n]+Config[ \t\r\n]*&" OR
       content MATCHES "Init(Outbounds|Router)[ \t\r\n]*\\([^)]*const[ \t\r\n]+Config[ \t\r\n]*&")
        message(FATAL_ERROR
            "Worker runtime boundary must not accept full Config; pass a prebuilt WorkerRuntimeConfig snapshot")
    endif()
endforeach()
