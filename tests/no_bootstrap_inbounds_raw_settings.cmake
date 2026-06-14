file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_inbounds.cpp" bootstrap_inbounds)

if(bootstrap_inbounds MATCHES "\\.settings")
    message(FATAL_ERROR
        "bootstrap_inbounds.cpp must consume prepared static inbound runtime entries, not raw inbound settings")
endif()
