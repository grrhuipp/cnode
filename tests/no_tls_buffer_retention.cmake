file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tls_stream.cpp" tls_source)

string(REGEX MATCHALL
    "SSL_CTX_set_mode\\([ \t\r\n]*ctx[ \t\r\n]*,[ \t\r\n]*SSL_MODE_RELEASE_BUFFERS[ \t\r\n]*\\)"
    ctx_release_buffer_modes
    "${tls_source}")
list(LENGTH ctx_release_buffer_modes ctx_release_buffer_mode_count)
if(ctx_release_buffer_mode_count LESS 3)
    message(FATAL_ERROR "All TLS SSL_CTX creation paths must enable SSL_MODE_RELEASE_BUFFERS")
endif()

set(constructor_name "TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx, bool is_server)")
string(FIND "${tls_source}" "${constructor_name}" constructor_pos)
if(constructor_pos EQUAL -1)
    message(FATAL_ERROR "TlsStream constructor must exist")
endif()

string(SUBSTRING "${tls_source}" ${constructor_pos} -1 constructor_tail)
string(FIND "${constructor_tail}" "TlsStream::~TlsStream()" destructor_pos)
if(destructor_pos EQUAL -1)
    message(FATAL_ERROR "Unable to isolate TlsStream constructor")
endif()
string(SUBSTRING "${constructor_tail}" 0 ${destructor_pos} constructor_source)

if(NOT constructor_source MATCHES
   "SSL_set_mode\\([ \t\r\n]*ssl_[ \t\r\n]*,[ \t\r\n]*SSL_MODE_RELEASE_BUFFERS[ \t\r\n]*\\)")
    message(FATAL_ERROR "TlsStream SSL objects must enable SSL_MODE_RELEASE_BUFFERS")
endif()
