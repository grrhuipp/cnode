file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config_types.hpp" config_types_header)
file(READ "${PROJECT_SOURCE_DIR}/src/infra/config.cpp" config_source)
file(READ "${PROJECT_SOURCE_DIR}/src/infra/config_loader.cpp" config_loader)

if(config_types_header MATCHES "struct[ \t\r\n]+InboundConfig[^A-Za-z0-9_]" OR
   config_types_header MATCHES "[^A-Za-z0-9_]InboundConfig[ \t\r\n]+FromJson" OR
   config_source MATCHES "[^A-Za-z0-9_:]InboundConfig::FromJson" OR
   config_loader MATCHES "[^A-Za-z0-9_:]InboundConfig::FromJson")
    message(FATAL_ERROR
        "Inbound static config parsing must produce StaticInboundConfig directly, not expose a raw InboundConfig shell")
endif()
