set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(FILE "${ROOT}/include/acppnode/app/udp_types.hpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing UDP types header: ${FILE}")
endif()

file(READ "${FILE}" content)

if(content MATCHES "struct[ \t\r\n]+UDPPacket[ \t\r\n{:]")
    message(FATAL_ERROR
        "app UDP public API must expose UDPPacketView only; owned UDP payloads use Buffer/MultiBuffer locally")
endif()
