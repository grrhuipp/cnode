file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config.hpp" config_header)

if(config_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*InboundConfig[ \t\r\n]*>[ \t\r\n]+inbounds_")
    message(FATAL_ERROR
        "Config runtime object must not retain raw InboundConfig storage; keep typed StaticInboundConfig runtime sources only")
endif()
