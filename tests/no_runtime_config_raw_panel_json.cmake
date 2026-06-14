file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/config.hpp" config_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_panels.cpp" bootstrap_panels)

if(config_header MATCHES "GetPanelEntries[ \t\r\n]*\\(" OR
   config_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*json::object[ \t\r\n]*>[ \t\r\n]+panels_")
    message(FATAL_ERROR
        "Runtime Config must not retain raw panel JSON; normalize panels to PanelConfig in the config cold path")
endif()

if(bootstrap_panels MATCHES "PanelConfig::FromJson[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Bootstrap panel setup must consume normalized PanelConfig entries, not parse raw panel JSON")
endif()
