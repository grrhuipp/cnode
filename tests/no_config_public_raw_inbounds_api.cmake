file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config.hpp" config_header)

if(config_header MATCHES "GetInbounds[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Config public API must expose typed static inbound runtime sources, not raw InboundConfig")
endif()
