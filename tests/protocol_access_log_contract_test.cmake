if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/proxy/vless/outbound/vless_outbound.cpp"
    VLESS_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/proxy/trojan/outbound/trojan_outbound.cpp"
    TROJAN_OUTBOUND_SOURCE)

foreach(SOURCE IN ITEMS VLESS_OUTBOUND_SOURCE TROJAN_OUTBOUND_SOURCE)
    if(NOT "${${SOURCE}}" MATCHES
           "result[.]bytes_up [+]= prewritten_bytes" OR
       NOT "${${SOURCE}}" MATCHES
           "ctx[.]traffic[.]bytes_up = result[.]bytes_up")
        message(FATAL_ERROR
            "${SOURCE}: prewritten proxy payload must remain visible to access logging")
    endif()
endforeach()
