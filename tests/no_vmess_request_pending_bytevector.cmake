set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(FILE "${ROOT}/src/proxy/vmess/vmess_request.hpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing VMess request header: ${FILE}")
endif()

file(READ "${FILE}" content)

if(content MATCHES "memory::ByteVector\\*[ \t\r\n]+pending_data_")
    message(FATAL_ERROR
        "VMessRequest must not keep pending first-packet data in ByteVector storage")
endif()
