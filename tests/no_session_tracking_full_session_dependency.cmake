file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/session_tracking.hpp" session_tracking_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/session_tracking.cpp" session_tracking_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp" dispatcher_source)

if(session_tracking_header MATCHES "common/session\\.hpp")
    message(FATAL_ERROR
        "session_tracking.hpp must not include full session runtime definitions; forward declare session::Traffic for pointer-only storage")
endif()

if(NOT session_tracking_header MATCHES "namespace[ \t\r\n]+session[ \t\r\n]*\\{[ \t\r\n]*struct[ \t\r\n]+Traffic;")
    message(FATAL_ERROR
        "session_tracking.hpp must forward declare session::Traffic")
endif()

if(NOT session_tracking_source MATCHES "common/session\\.hpp")
    message(FATAL_ERROR
        "session_tracking.cpp must include common/session.hpp directly because it reads session::Traffic counters")
endif()

if(NOT dispatcher_source MATCHES "common/session\\.hpp")
    message(FATAL_ERROR
        "default_dispatcher.cpp must include common/session.hpp directly because it owns session::Context handling")
endif()
