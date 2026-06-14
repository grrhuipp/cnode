file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_setup.cpp" bootstrap_setup)

if(worker_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*OutboundConfig[ \t\r\n]*>[ \t\r\n]+outbounds" OR
   worker_header MATCHES "AddOutboundAsync[ \t\r\n]*\\([ \t\r\n]*OutboundConfig" OR
   worker_header MATCHES "InitOutbounds[ \t\r\n]*\\([ \t\r\n]*const[ \t\r\n]+std::vector[ \t\r\n]*<[ \t\r\n]*OutboundConfig")
    message(FATAL_ERROR
        "Worker runtime must not carry raw OutboundConfig; prepare outbound runtime entries in the config cold path")
endif()

if(worker_source MATCHES "NewHandler[ \t\r\n]*\\([ \t\r\n]*ob_config[ \t\r\n]*," OR
   worker_source MATCHES "AddOutboundAsync[ \t\r\n]*\\([ \t\r\n]*OutboundConfig")
    message(FATAL_ERROR
        "Worker must create outbound handlers from prepared runtime entries, not raw outbound JSON-backed config")
endif()

if(bootstrap_setup MATCHES "runtime_config\\.outbounds[ \t\r\n]*=[ \t\r\n]*config\\.GetOutbounds[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Bootstrap setup must prepare outbound runtime entries before creating workers")
endif()
