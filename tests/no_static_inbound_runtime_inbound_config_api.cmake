file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_runtime.hpp" static_inbound_runtime_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/static_inbound_runtime.cpp" static_inbound_runtime_source)

if(static_inbound_runtime_header MATCHES "[^A-Za-z0-9_]InboundConfig[^A-Za-z0-9_]" OR
   static_inbound_runtime_source MATCHES "[^A-Za-z0-9_]InboundConfig[^A-Za-z0-9_]")
    message(FATAL_ERROR
        "static_inbound_runtime must consume a typed static inbound runtime source, not raw InboundConfig")
endif()
