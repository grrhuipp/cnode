file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_cpp)

if(controller_cpp MATCHES "limiter,[ \t\r\n]*inbound\\.tag,[ \t\r\n]*inbound\\.proxy_protocol")
    message(FATAL_ERROR
        "Panel inbounds must not use their generated outbound as a fixed outbound")
endif()

if(NOT controller_cpp MATCHES "limiter,[ \t\r\n]*std::string\\{\\},[ \t\r\n]*inbound\\.proxy_protocol")
    message(FATAL_ERROR
        "Panel inbounds should leave fixed outbound empty so routing.json is applied")
endif()
