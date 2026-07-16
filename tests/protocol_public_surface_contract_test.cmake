if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

foreach(interface_header IN ITEMS inbound.hpp outbound.hpp)
    if(NOT EXISTS "${SOURCE_DIR}/include/acppnode/proxy/${interface_header}")
        message(FATAL_ERROR
            "missing public proxy interface: ${interface_header}")
    endif()
endforeach()

set(PUBLIC_PROXY_ROOT "${SOURCE_DIR}/include/acppnode/proxy")
file(GLOB_RECURSE PUBLIC_PROXY_HEADERS
    LIST_DIRECTORIES false
    "${PUBLIC_PROXY_ROOT}/*.hpp")
foreach(header IN LISTS PUBLIC_PROXY_HEADERS)
    get_filename_component(header_dir "${header}" DIRECTORY)
    if(NOT header_dir STREQUAL PUBLIC_PROXY_ROOT)
        message(FATAL_ERROR
            "protocol-specific headers must remain private to src/proxy: ${header}")
    endif()
endforeach()

set(INBOUND_MANAGER
    "${SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp")
file(READ "${INBOUND_MANAGER}" INBOUND_MANAGER_SOURCE)
if(INBOUND_MANAGER_SOURCE MATCHES "#include[ \t]+\"acppnode/proxy/")
    message(FATAL_ERROR
        "inbound Manager must not include concrete protocol implementation headers")
endif()
if(INBOUND_MANAGER_SOURCE MATCHES "constants::protocol::")
    message(FATAL_ERROR
        "inbound Manager must not branch on concrete protocol tags")
endif()
