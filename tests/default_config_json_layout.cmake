file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/core/constants.hpp" constants_header)
file(READ "${PROJECT_SOURCE_DIR}/docs/configuration.md" configuration_doc)
file(READ "${PROJECT_SOURCE_DIR}/docs/architecture.md" architecture_doc)
file(READ "${PROJECT_SOURCE_DIR}/src/infra/config_loader.cpp" config_loader)
file(READ "${PROJECT_SOURCE_DIR}/scripts/cnode.sh" deploy_script)

if(NOT constants_header MATCHES "kDefaultConfigFile[^\n]*config\\.json")
    message(FATAL_ERROR "Default config file must be config.json")
endif()

if(constants_header MATCHES "kDefaultConfigFile[^\n]*config\\.yml")
    message(FATAL_ERROR "Default config file must not regress to config.yml")
endif()

if(configuration_doc MATCHES "```yaml" OR configuration_doc MATCHES "config\\.yml")
    message(FATAL_ERROR "Configuration docs must use JSON examples and config.json")
endif()

foreach(pattern IN ITEMS "ParseYaml" "IsYamlPath" "TokenizeYaml" "\\.ya?ml")
    if(config_loader MATCHES "${pattern}")
        message(FATAL_ERROR "cnode config loader must not keep YAML compatibility: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "kInboundFile[^\n]*inbounds\\.json"
        "kOutboundFile[^\n]*outbounds\\.json"
        "kRouteFile[^\n]*routing\\.json")
    if(NOT constants_header MATCHES "${pattern}")
        message(FATAL_ERROR "Sidecar constants must use xray-core plural layout: ${pattern}")
    endif()
endforeach()

foreach(content IN ITEMS "${configuration_doc}" "${deploy_script}")
    foreach(pattern IN ITEMS "inbound\\.json" "outbound\\.json" "route\\.json")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Docs/scripts must not advertise singular sidecar names: ${pattern}")
        endif()
    endforeach()
endforeach()

foreach(pattern IN ITEMS
        "config\\.json:inbounds"
        "config\\.json:outbounds"
        "config\\.json:routing")
    if(config_loader MATCHES "${pattern}")
        message(FATAL_ERROR "config.json must not load proxy sidecar content inline: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "SelectConfigList\\(\\*j, \"inbounds\"\\)"
        "SelectConfigList\\(\\*j, \"outbounds\"\\)"
        "ParseRoutingConfigValue\\(\\*j\\)")
    if(NOT config_loader MATCHES "${pattern}")
        message(FATAL_ERROR "Sidecar loader must accept xray-core-shaped wrapper objects: ${pattern}")
    endif()
endforeach()

foreach(pattern
        "default main file is[ \r\n]+`config.json`"
        "difference from XrayR"
        "xray-core object shapes"
        "inbounds.json"
        "outbounds.json"
        "routing.json"
        "config.json")
    if(NOT configuration_doc MATCHES "${pattern}")
        message(FATAL_ERROR "Configuration docs must document JSON layout: ${pattern}")
    endif()
endforeach()

foreach(pattern
        "默认主配置文件为 `config.json`"
        "与 XrayR[ \r\n]+YAML 配置布局有意不同")
    if(NOT architecture_doc MATCHES "${pattern}")
        message(FATAL_ERROR "Architecture doc must record cnode JSON-vs-XrayR YAML boundary: ${pattern}")
    endif()
endforeach()
