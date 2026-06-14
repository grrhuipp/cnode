file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/tcp_stream.hpp" header)
file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tcp_stream.cpp" source)

if(header MATCHES "memory::ByteVector\\*[ \t\r\n]+pending_data_")
    message(FATAL_ERROR
        "TcpStream must not keep pending data in a connection-level ByteVector; use Buffer/MultiBuffer ownership")
endif()

if(source MATCHES "EnsurePendingData\\(")
    message(FATAL_ERROR
        "TcpStream must not allocate pending data through ByteVector helper storage")
endif()

foreach(forbidden_header
        "common/allocator\\.hpp"
        "timeout_scheduler\\.hpp")
    if(header MATCHES "${forbidden_header}")
        message(FATAL_ERROR
            "tcp_stream.hpp must not expose allocator or timeout scheduler implementation dependencies")
    endif()
endforeach()

foreach(forbidden_storage
        "socket_"
        "timeout_scheduler_"
        "pending_data_"
        "last_io_time_"
        "idle_timer_token_"
        "read_deadline_token_"
        "write_deadline_token_"
        "phase_deadline_token_"
        "read_alloc_count_"
        "read_grow_streak_"
        "stream_label_"
        "flags_"
        "idle_timeout_sec_"
        "read_timeout_sec_"
        "write_timeout_sec_"
        "phase_deadline_generation_"
        "enum[ \t\r\n]+Flag"
        "StreamLabelKind")
    if(header MATCHES "${forbidden_storage}")
        message(FATAL_ERROR
            "TcpStream public header must not expose socket, timeout, pending buffer, read strategy, or flag storage")
    endif()
endforeach()

if(NOT header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "TcpStream should hide per-connection runtime state behind an implementation pointer")
endif()

if(NOT source MATCHES "struct[ \t\r\n]+TcpStream::Impl" OR
   NOT source MATCHES "tcp::socket[ \t\r\n]+socket" OR
   NOT source MATCHES "TimeoutScheduler\\*[ \t\r\n]+timeout_scheduler" OR
   NOT source MATCHES "buf::MultiBuffer[ \t\r\n]+pending_data")
    message(FATAL_ERROR
        "TcpStream implementation should privately own socket, timeout scheduler, and pending buffer storage")
endif()
