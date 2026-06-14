file(GLOB_RECURSE outbound_headers
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/*/outbound/*.hpp"
)
list(APPEND outbound_headers
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/freedom/freedom_outbound.hpp"
)

foreach(header IN LISTS outbound_headers)
    file(READ "${header}" content)
    if(content MATCHES "app/dns/dns\\.hpp")
        message(FATAL_ERROR
            "Protocol outbound public headers must not include the full DNS service header: ${header}")
    endif()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/freedom/freedom_outbound.hpp" freedom_header)
if(freedom_header MATCHES "ThreadLocalVector[ \t\r\n]*<[ \t\r\n]*net::ip::address")
    message(FATAL_ERROR
        "freedom outbound public header must not expose Worker-local address containers in helper signatures")
endif()

file(READ "${PROJECT_SOURCE_DIR}/src/proxy/freedom/freedom_outbound.cpp" freedom_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/vmess/outbound/vmess_outbound.cpp" vmess_cpp)

if(NOT freedom_cpp MATCHES "app/dns/dns\\.hpp")
    message(FATAL_ERROR
        "freedom_outbound.cpp must include the DNS service implementation header where DNS methods are used")
endif()

if(NOT vmess_cpp MATCHES "app/dns/dns\\.hpp")
    message(FATAL_ERROR
        "vmess_outbound.cpp must include the DNS service implementation header where DNS methods are used")
endif()
