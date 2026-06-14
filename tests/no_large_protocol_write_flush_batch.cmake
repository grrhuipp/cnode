set(protocol_write_files
    "${PROJECT_SOURCE_DIR}/src/proxy/vmess/encoding/client.cpp"
    "${PROJECT_SOURCE_DIR}/src/proxy/vmess/encoding/server.cpp"
    "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/client.cpp"
    "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/server.cpp")

foreach(file IN LISTS protocol_write_files)
    file(READ "${file}" content)

    if(NOT content MATCHES "kStreamFlushBufferCount[ \t\r\n]*=[ \t\r\n]*2")
        message(FATAL_ERROR
            "Protocol stream writers must cap output batching at two relay buffers: ${file}")
    endif()

    if(content MATCHES "kStreamFlushBufferCount[ \t\r\n]*=[ \t\r\n]*[3-9][0-9]*")
        message(FATAL_ERROR
            "Protocol stream writers must not restore large per-direction write batches: ${file}")
    endif()

    if(NOT content MATCHES "out_mb\\.reserve\\(kStreamFlushBufferCount\\)")
        message(FATAL_ERROR
            "Protocol stream writers must reserve only the capped flush batch: ${file}")
    endif()

    if(NOT content MATCHES "out_mb\\.size\\(\\)[ \t\r\n]*>=[ \t\r\n]*kStreamFlushBufferCount")
        message(FATAL_ERROR
            "Protocol stream writers must flush when the capped batch is full: ${file}")
    endif()
endforeach()
