file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/api/api.hpp" api_header)

if(api_header MATCHES "#include[ \t]+\"acppnode/common\\.hpp\"")
    message(FATAL_ERROR "Panel API public model header must not include the common umbrella")
endif()

if(api_header MATCHES "#include[ \t]+\"acppnode/infra/json\\.hpp\"" OR
   api_header MATCHES "json::")
    message(FATAL_ERROR "Panel API public model header must not expose raw JSON values")
endif()

foreach(required
    "#include[ \t]+\"acppnode/common/asio_types\\.hpp\""
    "#include[ \t]+\"acppnode/common/defaults\\.hpp\""
    "#include[ \t]+\"acppnode/common/error\\.hpp\""
    "#include[ \t]+\"acppnode/common/rule_types\\.hpp\""
    "#include[ \t]+\"acppnode/core/constants\\.hpp\"")
    if(NOT api_header MATCHES "${required}")
        message(FATAL_ERROR "Panel API public model header must spell out narrow dependencies: ${required}")
    endif()
endforeach()

if(api_header MATCHES "#include[ \t]+\"acppnode/service/controller/controller\\.hpp\"" OR
   api_header MATCHES "#include[ \t]+\"acppnode/service/controller/config\\.hpp\"" OR
   api_header MATCHES "#include[ \t]+\"acppnode/app/worker\\.hpp\"")
    message(FATAL_ERROR "Panel API public model header must not depend on controller or Worker hot-path headers")
endif()
