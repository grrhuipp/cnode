set(headers
    "include/acppnode/features/outbound/outbound.hpp"
    "include/acppnode/proxy/outbound.hpp"
    "include/acppnode/app/proxyman/outbound/handler.hpp"
    "include/acppnode/app/proxyman/outbound/factory.hpp"
    "include/acppnode/app/proxyman/inbound/handler.hpp"
    "include/acppnode/app/dispatcher/default_dispatcher.hpp"
    "include/acppnode/app/static_inbound_runtime.hpp"
)

foreach(path IN LISTS headers)
    file(READ "${PROJECT_SOURCE_DIR}/${path}" content)
    if(content MATCHES "infra/config\\.hpp")
        message(FATAL_ERROR
            "Hot-path public header ${path} must include config_types.hpp instead of the full Config class header")
    endif()
endforeach()
