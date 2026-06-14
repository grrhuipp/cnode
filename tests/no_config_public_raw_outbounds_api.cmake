file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config.hpp" config_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_setup.cpp" bootstrap_setup)

if(config_header MATCHES "GetOutbounds[ \t\r\n]*\\(" OR
   bootstrap_setup MATCHES "GetOutbounds[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Config public API must not expose raw OutboundConfig; app cold path must request prepared runtime outbounds")
endif()
