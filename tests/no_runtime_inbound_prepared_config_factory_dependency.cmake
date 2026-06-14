file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" worker_runtime_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_runtime.hpp" static_inbound_runtime)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_prepared_config.hpp" static_inbound_prepared_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/factory.hpp" inbound_factory)

function(require_inbound_prepared_config_boundary header_name header_content)
    if(header_content MATCHES "app/proxyman/inbound/factory\\.hpp")
        message(FATAL_ERROR
            "${header_name} must depend on inbound prepared runtime config, not the protocol factory API")
    endif()

    if(NOT header_content MATCHES "app/proxyman/inbound/prepared_config\\.hpp")
        message(FATAL_ERROR
            "${header_name} must include the inbound prepared runtime config boundary for BuildRequest/UserSet")
    endif()
endfunction()

require_inbound_prepared_config_boundary(
    "worker_runtime_config.hpp"
    "${worker_runtime_config}")
require_inbound_prepared_config_boundary(
    "static_inbound_prepared_config.hpp"
    "${static_inbound_prepared_config}")

if(static_inbound_runtime MATCHES "app/proxyman/inbound/factory\\.hpp")
    message(FATAL_ERROR
        "static_inbound_runtime.hpp must not include the protocol factory API")
endif()

if(NOT static_inbound_runtime MATCHES "app/static_inbound_prepared_config\\.hpp")
    message(FATAL_ERROR
        "static_inbound_runtime.hpp must include the static inbound prepared data boundary")
endif()

if(inbound_factory MATCHES "struct[ \t\r\n]+BuildRequest" OR
   inbound_factory MATCHES "struct[ \t\r\n]+UserSet")
    message(FATAL_ERROR
        "inbound factory.hpp must not own prepared runtime data types; keep BuildRequest/UserSet in prepared_config.hpp")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/prepared_config.hpp")
    message(FATAL_ERROR
        "inbound prepared_config.hpp must exist as the narrow runtime data boundary")
endif()
