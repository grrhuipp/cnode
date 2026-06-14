set(public_v2board_header "${PROJECT_SOURCE_DIR}/include/acppnode/api/v2board/v2board.hpp")
if(EXISTS "${public_v2board_header}")
    file(READ "${public_v2board_header}" header)
else()
    set(header "")
endif()

set(forbidden_public_helpers
    "HttpResponse"
    "HttpMethod"
    "UrlParts"
    "ExtractBlockDetectRules"
    "FormatHttpFailure"
)

foreach(symbol IN LISTS forbidden_public_helpers)
    if(header MATCHES "${symbol}")
        message(FATAL_ERROR "V2Board API header exposes private HTTP helper '${symbol}'")
    endif()
endforeach()

if(EXISTS "${public_v2board_header}")
    message(FATAL_ERROR "V2Board client implementation must not be exposed through a public api/v2board header")
endif()
