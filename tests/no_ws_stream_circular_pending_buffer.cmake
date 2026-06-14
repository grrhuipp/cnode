file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/ws_stream.hpp" ws_header)

if(ws_header MATCHES "CircularBuffer[ \t\r\n]+pending_data_")
    message(FATAL_ERROR
        "WebSocket stream must not keep connection-level CircularBuffer/ByteVector pending data; use Buffer/MultiBuffer ownership")
endif()
