file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/rule.hpp" rule_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/api/api.hpp" api_header)

function(require_no_api_header header_name header_content)
    if(header_content MATCHES "api/api\\.hpp")
        message(FATAL_ERROR
            "${header_name} must not include the full panel API header for detect rule runtime types")
    endif()
endfunction()

require_no_api_header("rule.hpp" "${rule_header}")
require_no_api_header("worker.hpp" "${worker_header}")

if(NOT rule_header MATCHES "common/rule_types\\.hpp")
    message(FATAL_ERROR
        "Rule manager public header must use the narrow detect rule runtime type boundary")
endif()

if(worker_header MATCHES "common/rule_types\\.hpp")
    message(FATAL_ERROR
        "Worker public header must not include detect rule DTO storage; keep rule DTOs behind forward declarations")
endif()

if(NOT worker_header MATCHES "struct[ \t\r\n]+DetectRule;" OR
   NOT worker_header MATCHES "struct[ \t\r\n]+DetectResult;")
    message(FATAL_ERROR
        "Worker public header must forward declare detect rule DTOs at the public task boundary")
endif()

if(api_header MATCHES "struct[ \t\r\n]+DetectRule" OR
   api_header MATCHES "struct[ \t\r\n]+DetectResult")
    message(FATAL_ERROR
        "api.hpp must alias detect rule runtime types instead of owning their definitions")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/common/rule_types.hpp")
    message(FATAL_ERROR
        "common/rule_types.hpp must exist as the narrow detect rule runtime data boundary")
endif()
