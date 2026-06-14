set(public_source_header "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/source_config.hpp")
if(EXISTS "${public_source_header}")
    message(FATAL_ERROR
        "OutboundSourceConfig must not live in the public include tree; raw outbound JSON source parsing belongs to the proxyman outbound cold-path implementation")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/factory.hpp" factory_header)
if(factory_header MATCHES "source_config\\.hpp" OR
   factory_header MATCHES "json::object" OR
   factory_header MATCHES "\\.settings")
    message(FATAL_ERROR
        "proxyman outbound factory public API must not expose raw outbound JSON source config details")
endif()

file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/outbound/source_config.hpp" private_source_header)
if(NOT private_source_header MATCHES "struct[ \t\r\n]+OutboundSourceConfig" OR
   NOT private_source_header MATCHES "json::object[ \t\r\n]+settings")
    message(FATAL_ERROR
        "OutboundSourceConfig should remain a private cold-path source parser while protocol prepare functions are being migrated")
endif()
