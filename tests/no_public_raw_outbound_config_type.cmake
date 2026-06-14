file(READ "${CMAKE_CURRENT_LIST_DIR}/../include/acppnode/infra/config_types.hpp" config_types)

if(config_types MATCHES "struct[ \t\r\n]+OutboundConfig")
    message(FATAL_ERROR
        "infra config types must not expose raw OutboundConfig; outbound source parsing belongs to the proxyman outbound cold path")
endif()
