file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp" inbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp" outbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tls_stream.cpp" tls_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/ws_stream.hpp" ws_source)

if(NOT inbound_source MATCHES "if[ \t\r\n]*\\(stream_\\)[ \t\r\n]*\\{[ \t\r\n]*stream_->CloseAbortive\\(\\);")
    message(FATAL_ERROR "AnyTLS inbound physical demux session must abortively close its underlying stream")
endif()

if(inbound_source MATCHES "if[ \t\r\n]*\\(stream_\\)[ \t\r\n]*\\{[ \t\r\n]*stream_->Cancel\\(\\);")
    message(FATAL_ERROR "AnyTLS inbound physical demux session must not leave the stream only cancelled")
endif()

if(inbound_source MATCHES "if[ \t\r\n]*\\(stream_\\)[ \t\r\n]*\\{[ \t\r\n]*stream_->Close\\(\\);")
    message(FATAL_ERROR "AnyTLS inbound physical demux session must not use graceful Close on teardown")
endif()

if(NOT outbound_source MATCHES "if[ \t\r\n]*\\(stream\\)[ \t\r\n]*\\{[ \t\r\n]*stream->CloseAbortive\\(\\);")
    message(FATAL_ERROR "AnyTLS outbound physical session must abortively close its underlying stream")
endif()

if(outbound_source MATCHES "if[ \t\r\n]*\\(stream\\)[ \t\r\n]*\\{[ \t\r\n]*stream->Cancel\\(\\);")
    message(FATAL_ERROR "AnyTLS outbound physical session must not leave the stream only cancelled")
endif()

if(outbound_source MATCHES "if[ \t\r\n]*\\(stream\\)[ \t\r\n]*\\{[ \t\r\n]*stream->Close\\(\\);")
    message(FATAL_ERROR "AnyTLS outbound physical session must not use graceful Close on teardown")
endif()

string(REGEX MATCH
    "void[ \t\r\n]+TlsStream::CloseAbortive[ \t\r\n]*\\([ \t\r\n]*\\)[ \t\r\n]*\\{[^}]*\\}"
    tls_abortive_body
    "${tls_source}")

if(tls_abortive_body STREQUAL "")
    message(FATAL_ERROR "TlsStream must implement CloseAbortive")
endif()

if(tls_abortive_body MATCHES "SSL_shutdown")
    message(FATAL_ERROR "TlsStream::CloseAbortive must not perform TLS graceful shutdown")
endif()

if(NOT tls_abortive_body MATCHES "inner_\\.SetAbortiveClose\\(true\\);[ \t\r\n]*inner_\\.Close\\(\\);")
    message(FATAL_ERROR "TlsStream::CloseAbortive must abortively close the underlying TCP stream")
endif()

if(NOT ws_source MATCHES "void[ \t\r\n]+CloseAbortive[ \t\r\n]*\\([ \t\r\n]*\\)[ \t\r\n]+override")
    message(FATAL_ERROR "WebSocket streams must override abortive close")
endif()

if(NOT ws_source MATCHES "inner_->CloseAbortive\\(\\);")
    message(FATAL_ERROR "WebSocket streams must propagate abortive close through wrapper chains")
endif()
