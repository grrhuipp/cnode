if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/transport/internet/tcp_stream.cpp"
    TCP_STREAM_SOURCE)
file(READ
    "${SOURCE_DIR}/src/transport/internet/tls_stream.cpp"
    TLS_STREAM_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/transport/internet/ws_stream.hpp"
    WS_STREAM_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/transport/async_stream.hpp"
    ASYNC_STREAM_HEADER)
file(READ
    "${SOURCE_DIR}/src/transport/internet/transport_stack.cpp"
    TRANSPORT_STACK_SOURCE)
file(READ
    "${SOURCE_DIR}/README.md"
    README_SOURCE)

set(READ_START_MARKER
    "net::awaitable<buf::MultiBuffer> TcpStream::ReadMultiBuffer() {")
set(READ_END_MARKER "// TcpStream::WriteMultiBuffer")
string(FIND "${TCP_STREAM_SOURCE}" "${READ_START_MARKER}" READ_START)
string(FIND "${TCP_STREAM_SOURCE}" "${READ_END_MARKER}" READ_END)
if(READ_START EQUAL -1 OR READ_END EQUAL -1 OR NOT READ_START LESS READ_END)
    message(FATAL_ERROR "TcpStream::ReadMultiBuffer source range not found")
endif()

math(EXPR READ_LENGTH "${READ_END} - ${READ_START}")
string(SUBSTRING "${TCP_STREAM_SOURCE}" ${READ_START} ${READ_LENGTH} READ_SOURCE)
string(REGEX MATCHALL "Buffer::New[(][)]" READ_ALLOCATIONS "${READ_SOURCE}")
list(LENGTH READ_ALLOCATIONS READ_ALLOCATION_COUNT)
string(FIND "${READ_SOURCE}" "co_await WaitReadable()" READ_WAIT)
string(FIND "${READ_SOURCE}" "Buffer::New()" READ_ALLOCATION)

if(NOT READ_ALLOCATION_COUNT EQUAL 1 OR
   READ_SOURCE MATCHES "scatter-read|read_alloc_count|kMaxReadAllocBuffers" OR
   READ_WAIT EQUAL -1 OR READ_ALLOCATION EQUAL -1 OR
   NOT READ_WAIT LESS READ_ALLOCATION OR
   NOT READ_SOURCE MATCHES
       "async_read_some[(][\n\r ]*net::mutable_buffer[(]buffer->Tail[(][)][.]data[(][)], buffer->Available[(][)][)]")
    message(FATAL_ERROR
        "each TCP relay direction must keep exactly one pending 8KB payload Buffer")
endif()

set(TLS_READ_START_MARKER
    "net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer() {")
set(TLS_READ_END_MARKER
    "net::awaitable<std::size_t> TlsStream::AsyncWrite")
string(FIND "${TLS_STREAM_SOURCE}" "${TLS_READ_START_MARKER}" TLS_READ_START)
string(FIND "${TLS_STREAM_SOURCE}" "${TLS_READ_END_MARKER}" TLS_READ_END)
if(TLS_READ_START EQUAL -1 OR TLS_READ_END EQUAL -1 OR
   NOT TLS_READ_START LESS TLS_READ_END)
    message(FATAL_ERROR "TlsStream::ReadMultiBuffer source range not found")
endif()
math(EXPR TLS_READ_LENGTH "${TLS_READ_END} - ${TLS_READ_START}")
string(SUBSTRING "${TLS_STREAM_SOURCE}"
    ${TLS_READ_START} ${TLS_READ_LENGTH} TLS_READ_SOURCE)
string(FIND "${TLS_READ_SOURCE}" "co_await tcp->WaitReadable()" TLS_WAIT)
string(FIND "${TLS_READ_SOURCE}" "Buffer::New()" TLS_ALLOCATION)
if(TLS_WAIT EQUAL -1 OR TLS_ALLOCATION EQUAL -1 OR
   NOT TLS_WAIT LESS TLS_ALLOCATION OR
   NOT TLS_READ_SOURCE MATCHES "SSL_pending[(]ssl[)]" OR
   NOT TLS_READ_SOURCE MATCHES "SSL_has_pending[(]ssl[)]")
    message(FATAL_ERROR
        "TLS must wait for raw readability before allocating its payload Buffer")
endif()

set(WS_READ_START_MARKER
    "net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {")
string(FIND "${WS_STREAM_SOURCE}" "${WS_READ_START_MARKER}" WS_READ_START)
if(WS_READ_START EQUAL -1)
    message(FATAL_ERROR "BaseWsStream must own its lazy ReadMultiBuffer path")
endif()
string(SUBSTRING "${WS_STREAM_SOURCE}" ${WS_READ_START} -1 WS_READ_SOURCE)
string(FIND "${WS_READ_SOURCE}" "PrepareNextDataFrame()" WS_PREPARE)
string(FIND "${WS_READ_SOURCE}" "Buffer::New()" WS_ALLOCATION)
if(WS_PREPARE EQUAL -1 OR WS_ALLOCATION EQUAL -1 OR
   NOT WS_PREPARE LESS WS_ALLOCATION)
    message(FATAL_ERROR
        "WebSocket must parse a readable frame header before allocating payload")
endif()

if(NOT ASYNC_STREAM_HEADER MATCHES
       "ReadMultiBuffer[(][)][ ]*=[ ]*0[;]")
    message(FATAL_ERROR
        "AsyncStream must not provide an eager payload allocation fallback")
endif()

if(NOT TRANSPORT_STACK_SOURCE MATCHES
       "if [(]!co_await EnsureChunkPayload[(][)][)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "ReadMultiBuffer[(][)] override [{][\n\r ]*if [(]!co_await EnsureReadablePayload[(][)][)]" OR
   NOT TRANSPORT_STACK_SOURCE MATCHES
       "GrpcServerSubStreamState::ReadMultiBuffer[(][)] [{][\n\r ]*if [(]!co_await EnsureReadablePayload[(][)][)]")
    message(FATAL_ERROR
        "framed transports must await readable payload before Buffer allocation")
endif()

if(NOT README_SOURCE MATCHES
       "每个方向最多挂起一个 8KB payload Buffer，双向 payload 容量总计 16KB" OR
   NOT README_SOURCE MATCHES
       "空闲时先等待可读事件、不持有 payload Buffer")
    message(FATAL_ERROR
        "README must document the 16KB bidirectional payload-buffer contract")
endif()
