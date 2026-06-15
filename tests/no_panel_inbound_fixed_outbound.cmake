file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_cpp)

if(controller_cpp MATCHES "RoutePolicy::Fixed[ \t\r\n]*\\([ \t\r\n]*inbound\\.tag")
    message(FATAL_ERROR
        "Panel inbounds must not use their generated outbound as a fixed outbound")
endif()

if(NOT controller_cpp MATCHES "RoutePolicy::RouteWithFallback[ \t\r\n]*\\([ \t\r\n]*inbound\\.tag[ \t\r\n]*\\)")
    message(FATAL_ERROR
        "Panel inbounds should route first and use their generated outbound as the fallback")
endif()
