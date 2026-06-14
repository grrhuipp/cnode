set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(FILE "${ROOT}/include/acppnode/app/proxyman/inbound/udp_worker.hpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing UDP worker header: ${FILE}")
endif()

file(READ "${FILE}" content)

if(content MATCHES "memory::ByteVector[ \t\r\n]+payload[ \t\r\n]*;")
    message(FATAL_ERROR
        "UDP reply queue must not keep ByteVector payload storage; use Buffer/MultiBuffer ownership")
endif()
