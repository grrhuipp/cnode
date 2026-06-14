file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/outboundbuilder.hpp" outbound_builder_header)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/outboundbuilder.cpp" outbound_builder_source)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_control)

if(outbound_builder_header MATCHES "infra/config\\.hpp" OR
   outbound_builder_header MATCHES "[^A-Za-z0-9_:]OutboundConfig[ \t\r\n]+OutboundBuilder[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Controller outbound builder must return prepared runtime outbound entries, not raw OutboundConfig")
endif()

if(outbound_builder_source MATCHES "OutboundConfig[ \t\r\n]+config" OR
   outbound_builder_source MATCHES "json::object" OR
   outbound_builder_source MATCHES "\\.settings[ \t\r\n]*=")
    message(FATAL_ERROR
        "Controller outbound builder must not synthesize raw JSON settings for panel outbounds")
endif()

if(controller_control MATCHES "PrepareOutboundConfig[ \t\r\n]*\\([ \t\r\n]*outbound[ \t\r\n]*\\)")
    message(FATAL_ERROR
        "Controller outbound sync must receive prepared outbound entries directly from the builder")
endif()
