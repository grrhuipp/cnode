set(scan_files
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/config/config.json.example"
    "${PROJECT_SOURCE_DIR}/docs/configuration.md"
    "${PROJECT_SOURCE_DIR}/scripts/cnode.sh"
    "${PROJECT_SOURCE_DIR}/Dockerfile"
)

if(EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/api/v2board/v2board.hpp")
    message(FATAL_ERROR "Deleted public concrete V2Board client header has reappeared")
endif()

foreach(path IN LISTS scan_files)
    if(IS_DIRECTORY "${path}")
        file(GLOB_RECURSE files
            "${path}/*.hpp"
            "${path}/*.cpp"
            "${path}/*.h"
            "${path}/*.cc"
            "${path}/*.cxx"
        )
    else()
        set(files "${path}")
    endif()

    foreach(file IN LISTS files)
        file(READ "${file}" content)
        foreach(pattern
            "newV2board"
            "newv2board"
            "NewV2board"
            "dnsConfigPath"
            "inboundConfigPath"
            "outboundConfigPath"
            "routeConfigPath"
            "DnsConfigPath"
            "InboundConfigPath"
            "OutboundConfigPath"
            "RouteConfigPath"
            "api/v2board/v2board\\.hpp")
            if(content MATCHES "${pattern}")
                message(FATAL_ERROR "Final tree must not retain legacy public/config artifacts: ${file} matches ${pattern}")
            endif()
        endforeach()
    endforeach()
endforeach()

file(GLOB_RECURSE api_headers
    "${PROJECT_SOURCE_DIR}/include/acppnode/api/*.hpp"
)
foreach(file IN LISTS api_headers)
    file(READ "${file}" content)
    foreach(pattern IN ITEMS
        "APIClient"
        "JsonRequest"
        "JsonResponse"
        "SendRequest"
        "HTTPRequest")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Public panel API headers must not expose concrete V2Board HTTP client artifacts: ${file} matches ${pattern}")
        endif()
    endforeach()
endforeach()
