file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/memory_stats.hpp" stats_header)
file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tls_stream.cpp" tls_source)

if(NOT stats_header MATCHES "tls_streams_live" OR
   NOT stats_header MATCHES "OnTlsStreamNew" OR
   NOT stats_header MATCHES "OnTlsStreamFree")
    message(FATAL_ERROR "RuntimeMemoryStats must expose TLS stream live/peak counters")
endif()

if(NOT tls_source MATCHES "memory::OnTlsStreamNew\\(\\);" OR
   NOT tls_source MATCHES "memory::OnTlsStreamFree\\(\\);[ \t\r\n]*SSL_free\\(ssl_\\)")
    message(FATAL_ERROR "TlsStream must account active SSL stream lifetime")
endif()
