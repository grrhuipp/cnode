file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/manager.hpp" manager_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/outbound/manager.cpp" manager_source)

if(manager_header MATCHES "app/proxyman/outbound/handler\\.hpp")
    message(FATAL_ERROR
        "proxyman outbound manager public header must not include the concrete handler header; keep handler storage details in manager.cpp")
endif()

if(NOT manager_header MATCHES "features/outbound/outbound\\.hpp")
    message(FATAL_ERROR
        "proxyman outbound manager public header must depend only on the outbound feature manager interface")
endif()

if(NOT manager_header MATCHES "class[ \t\r\n]+Handler;")
    message(FATAL_ERROR
        "proxyman outbound manager public header must forward declare its concrete Handler type")
endif()

if(NOT manager_source MATCHES "app/proxyman/outbound/handler\\.hpp")
    message(FATAL_ERROR
        "proxyman outbound manager implementation must include the concrete handler header directly")
endif()
