file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/prepared_config.hpp" prepared_config)

if(prepared_config MATCHES "app/dns/dns\\.hpp")
    message(FATAL_ERROR
        "Outbound prepared config must not include the full DNS service header; the creator only needs a DNS reference")
endif()

if(prepared_config MATCHES "proxy/outbound\\.hpp")
    message(FATAL_ERROR
        "Outbound prepared config must not include the full outbound interface header; a forward declaration is enough for the creator return type")
endif()

if(prepared_config MATCHES "#include[ \t]+\"acppnode/common\\.hpp\"")
    message(FATAL_ERROR
        "Outbound prepared config must not include the common.hpp umbrella; use narrow Asio and explicit forward declarations")
endif()

if(NOT prepared_config MATCHES "#include[ \t]+\"acppnode/common/asio_types\\.hpp\"")
    message(FATAL_ERROR
        "Outbound prepared config must include the narrow Asio type boundary for net::io_context")
endif()

if(NOT prepared_config MATCHES "class[ \t\r\n]+Outbound;" OR
   NOT prepared_config MATCHES "namespace[ \t\r\n]+app::dns[ \t\r\n]*\\{[ \t\r\n]*class[ \t\r\n]+DNS;")
    message(FATAL_ERROR
        "Outbound prepared config must forward declare Outbound and app::dns::DNS instead of relying on common.hpp")
endif()
