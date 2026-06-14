file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/manager.hpp" manager_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp" manager_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_inbounds.cpp" bootstrap_inbounds)

foreach(header_name
        "app/proxyman/inbound/handler\\.hpp"
        "app/proxyman/inbound/udp_handler\\.hpp")
    if(manager_header MATCHES "${header_name}")
        message(FATAL_ERROR
            "proxyman inbound manager public header must not include concrete inbound handler headers")
    endif()
endforeach()

if(NOT manager_header MATCHES "class[ \t\r\n]+Handler;" OR
   NOT manager_header MATCHES "class[ \t\r\n]+UdpHandler;")
    message(FATAL_ERROR
        "proxyman inbound manager public header must forward declare Handler and UdpHandler")
endif()

if(NOT manager_header MATCHES "class[ \t\r\n]+Inbound;" OR
   NOT manager_header MATCHES "struct[ \t\r\n]+StatsShard;")
    message(FATAL_ERROR
        "proxyman inbound manager public header must explicitly forward declare Inbound and StatsShard after removing concrete handler headers")
endif()

if(NOT manager_source MATCHES "app/proxyman/inbound/handler\\.hpp" OR
   NOT manager_source MATCHES "app/proxyman/inbound/udp_handler\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager implementation must include concrete handler headers directly")
endif()

if(NOT worker_source MATCHES "app/proxyman/inbound/handler\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include inbound handler directly when it calls Handler methods")
endif()

if(NOT bootstrap_inbounds MATCHES "app/proxyman/inbound/udp_handler\\.hpp")
    message(FATAL_ERROR
        "bootstrap_inbounds.cpp must include udp_handler directly when it calls UdpHandler methods")
endif()
