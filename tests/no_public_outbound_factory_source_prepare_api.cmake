file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/factory.hpp" factory_header)

if(factory_header MATCHES "OutboundSourceConfig" OR
   factory_header MATCHES "RegisterProxy" OR
   factory_header MATCHES "PrepareOutboundConfig" OR
   factory_header MATCHES "PrepareOutboundConfigs")
    message(FATAL_ERROR
        "proxyman outbound public factory must expose prepared-runtime handler construction only; raw source registration/prepare API belongs to the private cold path")
endif()

file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/outbound/source_config.hpp" private_source_header)
if(NOT private_source_header MATCHES "RegisterProxy" OR
   NOT private_source_header MATCHES "PrepareOutboundConfig")
    message(FATAL_ERROR
        "private outbound source config header must own raw source registration and prepare API")
endif()
