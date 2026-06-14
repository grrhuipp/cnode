set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(FILE "${ROOT}/src/proxy/trojan/inbound/trojan_inbound.cpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing Trojan inbound implementation: ${FILE}")
endif()

file(READ "${FILE}" content)

if(content MATCHES "ThreadLocalDeque<UDPPacket>[ \t\r\n]+queue_")
    message(FATAL_ERROR
        "Trojan UDP framer queue must not store UDPPacket/ByteVector payloads")
endif()
