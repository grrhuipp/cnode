file(READ "${PROJECT_SOURCE_DIR}/src/app/static_inbound_runtime.cpp" static_inbound_runtime)

if(static_inbound_runtime MATCHES "json::object" OR
   static_inbound_runtime MATCHES "\\.settings" OR
   static_inbound_runtime MATCHES "if_contains[ \t\r\n]*\\([ \t\r\n]*\"(method|clients|id|password|email)\"")
    message(FATAL_ERROR
        "static_inbound_runtime.cpp must consume typed static inbound user config, not raw InboundConfig settings JSON")
endif()
