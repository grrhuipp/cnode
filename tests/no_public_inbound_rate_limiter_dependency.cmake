set(public_headers
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/inbound.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/manager.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/factory.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/vmess/inbound/vmess_inbound.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/trojan/inbound/trojan_inbound.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/shadowsocks/inbound/ss_inbound.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/anytls/inbound/anytls_inbound.hpp"
)

foreach(header_path IN LISTS public_headers)
    file(READ "${header_path}" header)
    if(header MATCHES "app/rate_limiter\\.hpp")
        message(FATAL_ERROR
            "public inbound/proxyman headers must not include the full rate_limiter implementation: ${header_path}")
    endif()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/rate_limiter_fwd.hpp" fwd_header)
if(NOT fwd_header MATCHES "class[ \t\r\n]+ConnectionLimiter")
    message(FATAL_ERROR
        "rate_limiter_fwd.hpp must forward declare ConnectionLimiter")
endif()
if(NOT fwd_header MATCHES "using[ \t\r\n]+ConnectionLimiterPtr[ \t\r\n]*=[ \t\r\n]*ConnectionLimiter\\*")
    message(FATAL_ERROR
        "rate_limiter_fwd.hpp must define the public ConnectionLimiterPtr alias")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/rate_limiter.hpp" full_header)
if(NOT full_header MATCHES "app/rate_limiter_fwd\\.hpp")
    message(FATAL_ERROR
        "the full rate_limiter header must include rate_limiter_fwd.hpp so direct users keep the pointer alias")
endif()
