file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_prepared_config.hpp" static_inbound_prepared_config)

if(static_inbound_prepared_config MATCHES "#include[ \t]+\"acppnode/infra/config_types\\.hpp\"")
    message(FATAL_ERROR
        "static_inbound_prepared_config.hpp must not include full config_types; prepared static inbound runtime data should depend on narrow stream/sniff data boundaries")
endif()

if(NOT static_inbound_prepared_config MATCHES "#include[ \t]+\"acppnode/transport/internet/stream_settings\\.hpp\"" OR
   NOT static_inbound_prepared_config MATCHES "#include[ \t]+\"acppnode/proxy/sniff_config\\.hpp\"")
    message(FATAL_ERROR
        "static_inbound_prepared_config.hpp should explicitly include the narrow stream and sniff config boundaries it stores")
endif()
