file(READ "${PROJECT_SOURCE_DIR}/src/infra/config_loader.cpp" config_loader)

if(config_loader MATCHES "#include[ \t\r\n]+\"acppnode/app/proxyman/outbound/factory\\.hpp\"")
    message(FATAL_ERROR
        "config_loader is a cold-path source parser and must depend on the private outbound source prepare boundary, not the public runtime handler factory")
endif()

if(NOT config_loader MATCHES "#include[ \t\r\n]+\"\\.\\./app/proxyman/outbound/source_config\\.hpp\"")
    message(FATAL_ERROR
        "config_loader must include the private outbound source prepare boundary for raw outbound file parsing")
endif()
