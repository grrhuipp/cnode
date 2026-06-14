set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(PUBLIC_HEADER "${ROOT}/include/acppnode/proxy/vmess/vmess_cipher.hpp")

if(EXISTS "${PUBLIC_HEADER}")
    message(FATAL_ERROR
        "VMess cipher helper must remain protocol-private, not a public include header: ${PUBLIC_HEADER}")
endif()
