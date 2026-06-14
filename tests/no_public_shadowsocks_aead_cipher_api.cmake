set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(PUBLIC_HEADER "${ROOT}/include/acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp")

file(READ "${PUBLIC_HEADER}" content)

set(FORBIDDEN_PATTERNS
    "class[ \t]+SsAeadCipher"
    "DeriveSubkey"
    "EVP_CIPHER_CTX"
    "openssl/evp\\.h"
)

foreach(pattern IN LISTS FORBIDDEN_PATTERNS)
    if(content MATCHES "${pattern}")
        message(FATAL_ERROR
            "Shadowsocks AEAD cipher helper must remain protocol-private: ${PUBLIC_HEADER} matches ${pattern}")
    endif()
endforeach()
