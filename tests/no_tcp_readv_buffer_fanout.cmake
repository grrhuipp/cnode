file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tcp_stream.cpp" tcp_source)

if(NOT tcp_source MATCHES "kMaxReadAllocBuffers[ \t\r\n]*=[ \t\r\n]*2")
    message(FATAL_ERROR "TcpStream scatter-read must cap pending read buffers at 2")
endif()

if(NOT tcp_source MATCHES
   "std::array<buf::BufferGuard,[ \t\r\n]*kMaxReadAllocBuffers>")
    message(FATAL_ERROR "TcpStream scatter-read BufferGuard array must use kMaxReadAllocBuffers")
endif()

if(NOT tcp_source MATCHES
   "std::array<net::mutable_buffer,[ \t\r\n]*kMaxReadAllocBuffers>")
    message(FATAL_ERROR "TcpStream scatter-read iovec array must use kMaxReadAllocBuffers")
endif()

if(tcp_source MATCHES "std::min\\([ \t\r\n]*n_alloc[ \t\r\n]*\\*[ \t\r\n]*2u[ \t\r\n]*,[ \t\r\n]*8u[ \t\r\n]*\\)")
    message(FATAL_ERROR "TcpStream scatter-read must not grow back to 8 pending relay buffers")
endif()
