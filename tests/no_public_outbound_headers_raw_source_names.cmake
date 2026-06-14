file(GLOB public_outbound_headers
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/*.hpp")

foreach(header IN LISTS public_outbound_headers)
    file(READ "${header}" content)
    if(content MATCHES "OutboundSourceConfig" OR
       content MATCHES "source[ \t-]+config" OR
       content MATCHES "raw[ \t-]+JSON" OR
       content MATCHES "raw[ \t-]+source")
        message(FATAL_ERROR
            "Public proxyman outbound headers must not mention raw source config details: ${header}")
    endif()
endforeach()
