set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(PUBLIC_HEADER "${ROOT}/include/acppnode/proxy/trojan/trojan_codec.hpp")

if(EXISTS "${PUBLIC_HEADER}")
    message(FATAL_ERROR
        "Trojan codec must remain protocol-private, not a public include header: ${PUBLIC_HEADER}")
endif()
