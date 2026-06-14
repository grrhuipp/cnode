file(READ "${PROJECT_SOURCE_DIR}/src/infra/config_loader.cpp" config_loader)

if(config_loader MATCHES "(direct|blackhole)\\.settings[ \t\r\n]*=" OR
   config_loader MATCHES "settings[ \t\r\n]*=[ \t\r\n]*json::object")
    message(FATAL_ERROR
        "config_loader built-in outbound fallbacks must not synthesize raw JSON settings; rely on typed cold-path defaults")
endif()
