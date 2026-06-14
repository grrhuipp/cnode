file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_runtime.hpp" static_inbound_runtime_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/static_inbound_runtime.cpp" static_inbound_runtime_source)

if(static_inbound_runtime_header MATCHES "#include[ \t]+\"acppnode/infra/config_types\\.hpp\"")
    message(FATAL_ERROR
        "static_inbound_runtime.hpp must not include full config_types; keep StaticInboundConfig complete type usage in the cold-path implementation")
endif()

if(NOT static_inbound_runtime_header MATCHES "struct[ \t\r\n]+StaticInboundConfig;")
    message(FATAL_ERROR
        "static_inbound_runtime.hpp should forward declare StaticInboundConfig for builder declarations")
endif()

if(NOT static_inbound_runtime_source MATCHES "#include[ \t]+\"acppnode/infra/config_types\\.hpp\"")
    message(FATAL_ERROR
        "static_inbound_runtime.cpp should include config_types.hpp where StaticInboundConfig fields are consumed")
endif()
