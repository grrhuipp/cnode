set(panel_paths
    "${PROJECT_SOURCE_DIR}/include/acppnode/api"
    "${PROJECT_SOURCE_DIR}/src/api"
)

foreach(path IN LISTS panel_paths)
    file(GLOB_RECURSE files
        "${path}/*.hpp"
        "${path}/*.cpp"
    )

    foreach(file IN LISTS files)
        file(READ "${file}" content)
        foreach(pattern
            "acppnode/app/worker\\.hpp"
            "acppnode/app/proxyman/"
            "NewInboundHandler"
            "NewUdpInboundHandler"
            "RegisterListenerAsync"
            "AddListenerAsync"
            "AddUdpListenerAsync"
            "UnregisterListenerAsync"
            "AddOutboundAsync"
            "RemoveOutboundAsync"
            "ApplyInboundUsersAsync"
            "AddInboundUsersAsync"
            "RemoveInboundUsersAsync"
            "ClearInboundUsersAsync"
            "proxyman::inbound"
            "proxyman::outbound")
            if(content MATCHES "${pattern}")
                message(FATAL_ERROR "Panel API/client code must not depend on Worker hot-path or live handler APIs: ${file} matches ${pattern}")
            endif()
        endforeach()
    endforeach()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_control)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/inboundbuilder.hpp" inbound_builder_header)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/outboundbuilder.hpp" outbound_builder_header)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/userbuilder.cpp" user_builder_source)

if(NOT controller_control MATCHES "controller::InboundBuilder" OR
   NOT controller_control MATCHES "controller::OutboundBuilder" OR
   NOT controller_control MATCHES "BuildUsersForInbound")
    message(FATAL_ERROR "Controller panel sync must build prepared inbound/outbound/users before touching Worker async APIs")
endif()

if(NOT inbound_builder_header MATCHES "proxyman::inbound::BuildRequest" OR
   NOT outbound_builder_header MATCHES "proxyman::outbound::PreparedOutboundConfig" OR
   NOT user_builder_source MATCHES "proxyman::inbound::UserSet")
    message(FATAL_ERROR "Controller builders must own the prepared runtime data boundaries for panel sync")
endif()
