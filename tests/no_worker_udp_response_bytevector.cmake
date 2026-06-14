file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)

if(worker_source MATCHES "memory::ByteVector[ \t\r\n]+payload[ \t\r\n]*\\([ \t\r\n]*encoded_len[ \t\r\n]*\\)")
    message(FATAL_ERROR
        "Worker UDP response encoding must not allocate a whole-packet ByteVector; encode into Buffer/MultiBuffer ownership")
endif()
