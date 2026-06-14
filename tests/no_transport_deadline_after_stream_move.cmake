file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/transport_dialer.cpp" dialer_cpp)

if(dialer_cpp MATCHES "std::move[ \t\r\n]*\\([ \t\r\n]*tcp_result\\.stream[ \t\r\n]*\\).*transport_deadline\\.Expired")
    message(FATAL_ERROR
        "transport dialer must not query a phase-deadline handle after moving the stream into BuildOutboundTransport")
endif()

if(dialer_cpp MATCHES "transport_deadline[ \t\r\n]*=" OR
   dialer_cpp MATCHES "transport_deadline\\.Expired")
    message(FATAL_ERROR
        "transport dialer must not keep a phase-deadline handle across outbound transport build ownership transfer")
endif()
