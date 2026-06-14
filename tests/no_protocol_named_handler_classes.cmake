set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(SCAN_FILES
    "${ROOT}/include/acppnode/proxy/anytls/inbound/anytls_inbound.hpp"
    "${ROOT}/include/acppnode/proxy/anytls/outbound/anytls_outbound.hpp"
    "${ROOT}/include/acppnode/proxy/freedom/freedom_outbound.hpp"
    "${ROOT}/include/acppnode/proxy/blackhole/blackhole_outbound.hpp"
)

set(FORBIDDEN_PATTERNS
    "AnyTLSInbound"
    "AnyTLSOutbound"
    "FreedomOutbound"
    "BlackholeOutbound"
)

foreach(file IN LISTS SCAN_FILES)
    if(NOT EXISTS "${file}")
        continue()
    endif()
    file(READ "${file}" content)
    foreach(pattern IN LISTS FORBIDDEN_PATTERNS)
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR
                "protocol public handler class must be named Handler: ${file} matches ${pattern}")
        endif()
    endforeach()
endforeach()
