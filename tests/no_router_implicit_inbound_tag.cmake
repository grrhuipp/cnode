file(READ "${PROJECT_SOURCE_DIR}/src/app/router/router.cpp" router_cpp)

if(router_cpp MATCHES "SetSingleInboundTagCondition")
    message(FATAL_ERROR
        "Router must not add an implicit inboundTag condition to routing rules")
endif()

if(router_cpp MATCHES "constants::protocol::kNode[^\\n]*inbound")
    message(FATAL_ERROR
        "Routing rules without inboundTag must match every inbound, like xray-core")
endif()

if(NOT router_cpp MATCHES "if[ \t\r\n]*\\(!rc\\.inbound_tag\\.empty\\(\\)\\)[ \t\r\n]*\\{[ \t\r\n]*compound\\.SetInboundTagCondition\\(rc\\.inbound_tag\\);[ \t\r\n]*\\}")
    message(FATAL_ERROR
        "Router should only apply inboundTag when the rule explicitly provides it")
endif()
