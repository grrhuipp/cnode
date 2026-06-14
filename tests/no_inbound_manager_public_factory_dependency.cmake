file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/manager.hpp" manager_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp" manager_cpp)

if(manager_header MATCHES "app/proxyman/inbound/factory\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager public header must not include the inbound factory registration boundary")
endif()

if(manager_header MATCHES "(ProtocolDeps|ProxyRegistration|RegisterProxy)")
    message(FATAL_ERROR
        "proxyman inbound manager public header must not expose factory registration or protocol dependency names")
endif()

if(NOT manager_header MATCHES "app/proxyman/inbound/prepared_config\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager public header should depend only on prepared inbound runtime data")
endif()

if(NOT manager_cpp MATCHES "app/proxyman/inbound/factory\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager implementation must include the factory registration boundary privately")
endif()
