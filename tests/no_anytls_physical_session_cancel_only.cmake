file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp" inbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp" outbound_source)

if(NOT inbound_source MATCHES "if[ \t\r\n]*\\(stream_\\)[ \t\r\n]*\\{[ \t\r\n]*stream_->Close\\(\\);")
    message(FATAL_ERROR "AnyTLS inbound physical demux session must close its underlying stream")
endif()

if(inbound_source MATCHES "if[ \t\r\n]*\\(stream_\\)[ \t\r\n]*\\{[ \t\r\n]*stream_->Cancel\\(\\);")
    message(FATAL_ERROR "AnyTLS inbound physical demux session must not leave the stream only cancelled")
endif()

if(NOT outbound_source MATCHES "if[ \t\r\n]*\\(stream\\)[ \t\r\n]*\\{[ \t\r\n]*stream->Close\\(\\);")
    message(FATAL_ERROR "AnyTLS outbound physical session must close its underlying stream")
endif()

if(outbound_source MATCHES "if[ \t\r\n]*\\(stream\\)[ \t\r\n]*\\{[ \t\r\n]*stream->Cancel\\(\\);")
    message(FATAL_ERROR "AnyTLS outbound physical session must not leave the stream only cancelled")
endif()
