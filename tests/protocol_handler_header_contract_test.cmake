if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

foreach(interface_header IN ITEMS inbound.hpp outbound.hpp)
    if(NOT EXISTS "${SOURCE_DIR}/include/acppnode/proxy/${interface_header}")
        message(FATAL_ERROR
            "missing public proxy interface: ${interface_header}")
    endif()
endforeach()

file(GLOB_RECURSE PUBLIC_HANDLER_HEADERS
    LIST_DIRECTORIES false
    "${SOURCE_DIR}/include/acppnode/proxy/*_inbound.hpp"
    "${SOURCE_DIR}/include/acppnode/proxy/*_outbound.hpp")
if(PUBLIC_HANDLER_HEADERS)
    list(SORT PUBLIC_HANDLER_HEADERS)
    string(JOIN "\n  " leaked_headers ${PUBLIC_HANDLER_HEADERS})
    message(FATAL_ERROR
        "concrete protocol handlers must remain private to src/proxy:\n  ${leaked_headers}")
endif()
