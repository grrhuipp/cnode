file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" runtime_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_setup.cpp" bootstrap_setup)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_inbounds.cpp" bootstrap_inbounds)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_inbounds.hpp" bootstrap_inbounds_header)

if(NOT runtime_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*StaticInboundRuntimeEntry[ \t\r\n]*>[ \t\r\n]+static_inbounds")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must carry prepared static inbound runtime entries in the immutable runtime snapshot")
endif()

if(runtime_header MATCHES "UserSet[ \t\r\n]+users")
    message(FATAL_ERROR
        "Static inbound runtime entries must not retain inbound user sets; users are published to global UserStore")
endif()

if(NOT bootstrap_setup MATCHES "BuildStaticInboundRuntimeEntries[ \t\r\n]*\\([ \t\r\n]*config\\.GetStaticInbounds\\(")
    message(FATAL_ERROR
        "Bootstrap cold path must build prepared static inbound entries while constructing WorkerRuntimeConfig")
endif()

if(bootstrap_inbounds MATCHES "BuildStaticInboundRuntimeEntries[ \t\r\n]*\\(" OR
   bootstrap_inbounds MATCHES "GetStaticInbounds[ \t\r\n]*\\(" OR
   bootstrap_inbounds MATCHES "#include[ \t\r\n]+\"acppnode/infra/config\\.hpp\"" OR
   bootstrap_inbounds_header MATCHES "const[ \t\r\n]+Config&[ \t\r\n]+config")
    message(FATAL_ERROR
        "Static inbound setup must consume prepared entries from WorkerRuntimeConfig, not bypass the runtime snapshot through Config")
endif()

if(NOT bootstrap_setup MATCHES "SetupStaticInbounds[ \t\r\n]*\\([ \t\r\n]*worker_runtime_config\\.static_inbounds")
    message(FATAL_ERROR
        "Bootstrap must register static inbounds from the WorkerRuntimeConfig snapshot")
endif()
