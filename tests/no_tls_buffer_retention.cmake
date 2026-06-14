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

set(async_write_name "net::awaitable<std::size_t> TlsStream::AsyncWrite(net::const_buffer buf)")
string(FIND "${tls_source}" "${async_write_name}" async_write_pos)
if(async_write_pos EQUAL -1)
    message(FATAL_ERROR "TlsStream::AsyncWrite must exist")
endif()

string(SUBSTRING "${tls_source}" ${async_write_pos} -1 async_write_tail)
string(FIND "${async_write_tail}" "void TlsStream::ShutdownRead()" next_function_pos)
if(next_function_pos EQUAL -1)
    message(FATAL_ERROR "Unable to isolate TlsStream::AsyncWrite")
endif()
string(SUBSTRING "${async_write_tail}" 0 ${next_function_pos} async_write_source)

if(NOT async_write_source MATCHES
   "std::min<std::size_t>\\([ \t\r\n]*remaining[ \t\r\n]*,[ \t\r\n]*kTlsIoBufferSize[ \t\r\n]*\\)")
    message(FATAL_ERROR "TlsStream::AsyncWrite must cap SSL_write chunks to the TLS IO buffer size")
endif()
if(NOT async_write_source MATCHES
   "SSL_write\\([ \t\r\n]*ssl_[ \t\r\n]*,[ \t\r\n]*data[ \t\r\n]*\\+[ \t\r\n]*total_written[ \t\r\n]*,[ \t\r\n]*to_write[ \t\r\n]*\\)")
    message(FATAL_ERROR "TlsStream::AsyncWrite must pass the capped chunk size to SSL_write")
endif()
