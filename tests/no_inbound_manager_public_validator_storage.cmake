file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/manager.hpp" manager_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp" manager_cpp)

if(manager_header MATCHES "proxy/(vmess|trojan|shadowsocks)/validator\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager public header must not include protocol validator implementation headers")
endif()

if(manager_header MATCHES "(TimedUserValidator|trojan::Validator|ss::Validator)")
    message(FATAL_ERROR
        "proxyman inbound manager public header must not expose protocol validator storage or concrete validator types")
endif()

if(NOT manager_header MATCHES "struct Impl;")
    message(FATAL_ERROR
        "proxyman inbound manager must hide protocol validator storage behind a private implementation boundary")
endif()

if(NOT manager_cpp MATCHES "proxy/vmess/validator\\.hpp" OR
   NOT manager_cpp MATCHES "proxy/trojan/validator\\.hpp" OR
   NOT manager_cpp MATCHES "proxy/shadowsocks/validator\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager implementation must own the protocol validator implementation dependencies")
endif()
