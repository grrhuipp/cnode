set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(FILE "${ROOT}/src/common/mux/mux_relay.cpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing Mux relay implementation: ${FILE}")
endif()

file(READ "${FILE}" content)

if(content MATCHES "memory::ByteVector[ \t\r\n]+frame_buf[ \t\r\n]*;")
    message(FATAL_ERROR
        "Mux frame parser must not keep a persistent ByteVector frame buffer")
endif()
