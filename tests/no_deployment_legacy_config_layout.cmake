set(scan_files
    "${PROJECT_SOURCE_DIR}/docs/configuration.md"
    "${PROJECT_SOURCE_DIR}/config/config.json.example"
    "${PROJECT_SOURCE_DIR}/scripts/cnode.sh"
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
    "${PROJECT_SOURCE_DIR}/config/config.json.example"
    "${PROJECT_SOURCE_DIR}/scripts/cnode.sh")
    file(READ "${file}" content)
    if(content MATCHES "\"DNSType\"" OR content MATCHES "\"ProxyProtocol\"")
        message(FATAL_ERROR "Deployment examples/scripts should rely on final DNSType/ProxyProtocol defaults instead of writing those fields: ${file}")
    endif()
    if(NOT content MATCHES "\"EnableDNS\"[ \t\r\n]*:[ \t\r\n]*true" AND
       NOT content MATCHES "EnableDNS:[ \t\r\n]*true")
        message(FATAL_ERROR "Deployment examples/scripts must default EnableDNS to true: ${file}")
    endif()
endforeach()

if(NOT configuration_doc MATCHES "When `ProxyProtocol` is omitted, cnode uses `\"auto\"`")
    message(FATAL_ERROR "Configuration docs must describe omitted ProxyProtocol default")
endif()
if(NOT configuration_doc MATCHES "`EnableDNS` defaults to[ \r\n]+`true`")
    message(FATAL_ERROR "Configuration docs must describe EnableDNS default true")
endif()
