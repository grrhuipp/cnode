file(READ "${PROJECT_SOURCE_DIR}/src/transport/internet/tcp_stream.cpp" tcp_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/tcp_stream.hpp" tcp_header)

if(NOT tcp_header MATCHES "DisarmWriteDeadline\\(\\)[ \t\r\n]+noexcept" OR
   NOT tcp_header MATCHES "ScheduleWriteDeadlineCheck\\(\\)")
    message(FATAL_ERROR "TcpStream must expose lazy write deadline helpers")
endif()

if(NOT tcp_source MATCHES "void[ \t\r\n]+TcpStream::DisarmWriteDeadline\\(\\)[ \t\r\n]+noexcept" OR
   NOT tcp_source MATCHES "void[ \t\r\n]+TcpStream::ScheduleWriteDeadlineCheck\\(\\)")
    message(FATAL_ERROR "TcpStream must implement lazy write deadline checks")
endif()

if(NOT tcp_source MATCHES "impl_->write_deadline_at[ \t\r\n]*=[ \t\r\n]*steady_clock::now\\(\\)[ \t\r\n]*\\+[ \t\r\n]*SecondsFromU32\\(impl_->write_timeout_sec\\)" OR
   NOT tcp_source MATCHES "if[ \t\r\n]*\\(!impl_->write_deadline_token\\.Valid\\(\\)\\)[ \t\r\n]*\\{[ \t\r\n]*ScheduleWriteDeadlineCheck\\(\\);")
    message(FATAL_ERROR "ArmWriteDeadline must update deadline without rescheduling on every write")
endif()

string(REGEX MATCHALL "DisarmWriteDeadline\\(\\);" disarm_calls "${tcp_source}")
list(LENGTH disarm_calls disarm_count)
if(disarm_count LESS 3)
    message(FATAL_ERROR "write completion must use DisarmWriteDeadline on the hot path")
endif()

if(tcp_source MATCHES "net::async_write\\([^;]+;[ \t\r\n]*CancelWriteDeadline\\(\\);")
    message(FATAL_ERROR "Write completion must disarm, not cancel/reschedule the shared timer")
endif()

if(tcp_source MATCHES "void[ \t\r\n]+TcpStream::DisarmWriteDeadline\\(\\)[^{]*\\{[^}]*SetFlag\\(kWriteTimedOut")
    message(FATAL_ERROR "DisarmWriteDeadline must preserve timeout flags for error mapping")
endif()
