file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/session.hpp" session_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp" dispatcher_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/common/mux/mux_relay.cpp" mux_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/freedom/freedom_outbound.cpp" freedom_cpp)

if(NOT session_header MATCHES "std::optional<tcp::endpoint>[ \t\r\n]+local_endpoint")
    message(FATAL_ERROR
        "session inbound metadata must carry the accepted local endpoint for source-in/source-out routing")
endif()

if(NOT worker_cpp MATCHES "ctx\\.inbound\\.local_endpoint[ \t\r\n]*=[ \t\r\n]*tcp::endpoint")
    message(FATAL_ERROR
        "worker must store the accepted TCP local endpoint in session context")
endif()

if(NOT dispatcher_cpp MATCHES "ctx\\.inbound\\.local_endpoint")
    message(FATAL_ERROR
        "dispatcher must recover inbound local endpoint from session context when protocol links hide the socket")
endif()

if(NOT mux_cpp MATCHES "sub_ctx\\.inbound\\.local_endpoint[ \t\r\n]*=[ \t\r\n]*parent_ctx\\.inbound\\.local_endpoint")
    message(FATAL_ERROR
        "Mux TCP sub-sessions must inherit the parent inbound local endpoint")
endif()

if(NOT mux_cpp MATCHES "sub->ctx\\.inbound\\.local_endpoint[ \t\r\n]*\\?[ \t\r\n]*&\\*sub->ctx\\.inbound\\.local_endpoint[ \t\r\n]*:[ \t\r\n]*nullptr")
    message(FATAL_ERROR
        "Mux TCP sub-dispatch must pass the inherited local endpoint to outbound handlers")
endif()

if(NOT freedom_cpp MATCHES "settings\\.send_through[ \t\r\n]*==[ \t\r\n]*constants::binding::kAuto" OR
   NOT freedom_cpp MATCHES "ctx\\.inbound\\.local_endpoint")
    message(FATAL_ERROR
        "Freedom UDP auto sendThrough must also use the inbound local endpoint when available")
endif()
