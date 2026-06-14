file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tls_stream.cpp" tls_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/tls_stream.hpp" tls_header)

if(NOT tls_header MATCHES "kTlsIoBufferSize[ \t\r\n]*=[ \t\r\n]*4096")
    message(FATAL_ERROR "TlsStream per-read encrypted scratch must stay at 4KB")
endif()

if(NOT tls_source MATCHES "kFlushBufSize[ \t\r\n]*=[ \t\r\n]*4[ \t\r\n]*\\*[ \t\r\n]*1024")
    message(FATAL_ERROR "TlsStream write BIO flush scratch must stay at 4KB or below")
endif()

set(function_name "net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer()")
string(FIND "${tls_source}" "${function_name}" function_pos)
if(function_pos EQUAL -1)
    message(FATAL_ERROR "TlsStream::ReadMultiBuffer must exist")
endif()

string(SUBSTRING "${tls_source}" ${function_pos} -1 tls_tail)
string(FIND "${tls_tail}" "net::awaitable<std::size_t> TlsStream::AsyncWrite" next_function_pos)
if(next_function_pos EQUAL -1)
    message(FATAL_ERROR "Unable to isolate TlsStream::ReadMultiBuffer body")
endif()
string(SUBSTRING "${tls_tail}" 0 ${next_function_pos} read_multibuffer_source)

string(FIND "${read_multibuffer_source}"
    "SSL_pending(ssl_) <= 0 && BIO_pending(read_bio_) <= 0"
    pending_check_pos)
if(pending_check_pos EQUAL -1)
    message(FATAL_ERROR "TlsStream::ReadMultiBuffer must check TLS/BIO pending state before allocating relay Buffer")
endif()

string(FIND "${read_multibuffer_source}" "SSL_peek" peek_pos)
if(peek_pos EQUAL -1)
    message(FATAL_ERROR "TlsStream::ReadMultiBuffer must probe TLS state without consuming app data before blocking on TCP")
endif()

string(FIND "${read_multibuffer_source}" "co_await inner_.AsyncRead" first_tcp_read_pos)
string(FIND "${read_multibuffer_source}" "buf::BufferGuard out" first_buffer_pos)
if(first_tcp_read_pos EQUAL -1 OR first_buffer_pos EQUAL -1)
    message(FATAL_ERROR "TlsStream::ReadMultiBuffer must contain both TCP read and relay Buffer allocation")
endif()

if(NOT first_tcp_read_pos LESS first_buffer_pos)
    message(FATAL_ERROR "TlsStream::ReadMultiBuffer must not hold an output relay Buffer while waiting for encrypted TCP input")
endif()
