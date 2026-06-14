file(READ "${CMAKE_CURRENT_LIST_DIR}/../include/acppnode/infra/config.hpp" config_header)

if(config_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*OutboundConfig[ \t\r\n]*>[ \t\r\n]+outbounds_")
    message(FATAL_ERROR
        "Config runtime object must not store raw OutboundConfig; config cold path must store prepared outbound runtime entries")
endif()
