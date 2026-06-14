file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config_types.hpp" config_types_header)

if(config_types_header MATCHES "#include[ \t]+\"acppnode/common\\.hpp\"")
    message(FATAL_ERROR
        "config_types.hpp must not include the common.hpp umbrella; config data should use narrow constants/defaults/json boundaries")
endif()

if(NOT config_types_header MATCHES "#include[ \t]+\"acppnode/core/constants\\.hpp\"" OR
   NOT config_types_header MATCHES "#include[ \t]+\"acppnode/common/defaults\\.hpp\"")
    message(FATAL_ERROR
        "config_types.hpp should include the narrow constants/defaults boundaries it uses")
endif()
