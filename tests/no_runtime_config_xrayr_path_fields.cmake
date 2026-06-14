file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config.hpp" config_header)
file(READ "${PROJECT_SOURCE_DIR}/src/infra/config.cpp" config_source)

foreach(field
        dns_config_path_
        inbound_config_path_
        outbound_config_path_
        route_config_path_)
    if(config_header MATCHES "${field}" OR config_source MATCHES "${field}")
        message(FATAL_ERROR
            "Runtime Config must not retain XrayR *ConfigPath fields; resolve external config files in config_loader cold path")
    endif()
endforeach()
