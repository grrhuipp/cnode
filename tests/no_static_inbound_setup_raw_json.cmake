file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_inbounds.cpp" bootstrap_inbounds)

if(bootstrap_inbounds MATCHES "inbound\\.settings\\.if_contains[ \t\r\n]*\\(" OR
   bootstrap_inbounds MATCHES "BuildStaticUsers[ \t\r\n]*\\([^)]*inbound\\.settings")
    message(FATAL_ERROR
        "Static inbound setup must consume a normalized cold-path runtime entry, not read raw inbound.settings in the registration loop")
endif()
