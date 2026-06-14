set(scan_files
    "${PROJECT_SOURCE_DIR}/docs/configuration.md"
    "${PROJECT_SOURCE_DIR}/config/config.json.example"
    "${PROJECT_SOURCE_DIR}/scripts/cnode.sh"
    "${PROJECT_SOURCE_DIR}/Dockerfile"
)

foreach(file IN LISTS scan_files)
    file(READ "${file}" content)
    foreach(pattern
        "DnsConfigPath"
        "InboundConfigPath"
        "OutboundConfigPath"
        "RouteConfigPath"
        "dnsConfigPath"
        "inboundConfigPath"
        "outboundConfigPath"
        "routeConfigPath"
        "newV2board"
        "newv2board"
        "NewV2board")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Deployment docs/examples/scripts must not advertise legacy config layout: ${file} matches ${pattern}")
        endif()
    endforeach()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/scripts/cnode.sh" deploy_script)
if(deploy_script MATCHES "select\\(\\.name[ \t\r\n]*!=")
    message(FATAL_ERROR "Deployment script must de-duplicate panels by final schema field Name, not legacy/lowercase name")
endif()
if(NOT deploy_script MATCHES "select\\(\\.Name[ \t\r\n]*!=")
    message(FATAL_ERROR "Deployment script must de-duplicate JSON panels by final schema field Name")
endif()

file(READ "${PROJECT_SOURCE_DIR}/docs/configuration.md" configuration_doc)
if(configuration_doc MATCHES "boolean values are still accepted" OR
   configuration_doc MATCHES "true[ \t\r\n]+maps to" OR
   configuration_doc MATCHES "false[ \t\r\n]+maps to")
    message(FATAL_ERROR "Configuration docs must describe the final ProxyProtocol string schema, not legacy boolean compatibility")
endif()

foreach(file IN ITEMS
    "${PROJECT_SOURCE_DIR}/docs/configuration.md"
    "${PROJECT_SOURCE_DIR}/config/config.json.example"
    "${PROJECT_SOURCE_DIR}/scripts/cnode.sh")
    file(READ "${file}" content)
    if(NOT content MATCHES "ProxyProtocol[^\n\r]*(auto|\\\"auto\\\")")
        message(FATAL_ERROR "Deployment docs/examples/scripts must use final ProxyProtocol string values: ${file}")
    endif()
endforeach()
