file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/outboundbuilder.hpp" outbound_builder_header)

if(outbound_builder_header MATCHES "#include[ \t\r\n]+\"acppnode/app/proxyman/outbound/factory\\.hpp\"")
    message(FATAL_ERROR
        "Controller outbound builder must depend on prepared outbound config only, not the public runtime handler factory")
endif()

if(NOT outbound_builder_header MATCHES "#include[ \t\r\n]+\"acppnode/app/proxyman/outbound/prepared_config\\.hpp\"")
    message(FATAL_ERROR
        "Controller outbound builder must include the prepared outbound config boundary for its return type")
endif()
