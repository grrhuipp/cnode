file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/stream_settings.hpp" stream_settings_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/tls_stream.hpp" tls_stream_header)

if(stream_settings_header MATCHES "#include[ \t]+\"acppnode/transport/internet/tls_stream\\.hpp\"")
    message(FATAL_ERROR
        "stream_settings.hpp must not include the TLS stream implementation header; it should depend only on TLS config data")
endif()

if(NOT stream_settings_header MATCHES "#include[ \t]+\"acppnode/transport/internet/tls_config\\.hpp\"")
    message(FATAL_ERROR
        "stream_settings.hpp should include the narrow TLS config data boundary")
endif()

if(tls_stream_header MATCHES "struct[ \t\r\n]+TlsConfig[ \t\r\n]*\\{")
    message(FATAL_ERROR
        "TlsConfig must live in tls_config.hpp, not in the TLS stream implementation header")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/tls_config.hpp")
    message(FATAL_ERROR "tls_config.hpp must exist as the narrow TLS config data boundary")
endif()
