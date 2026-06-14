set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(FILE "${ROOT}/src/app/relay_udp.cpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing UDP relay implementation: ${FILE}")
endif()

file(READ "${FILE}" content)

if(content MATCHES "ThreadLocalDeque<UDPPacket>[ \t\r\n]+reply_queue")
    message(FATAL_ERROR
        "UDP relay reply queue must not store UDPPacket/ByteVector payloads; use MultiBuffer ownership")
endif()
