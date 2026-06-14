file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/buf/multi_buffer.hpp" header)

if(header MATCHES "ThreadLocalVector[ \t\r\n]*<[ \t\r\n]*Buffer\\*" OR
   header MATCHES "memory::ThreadLocalVector[ \t\r\n]*<[ \t\r\n]*Buffer\\*")
    message(FATAL_ERROR
        "MultiBuffer public type must not expose Worker-local allocator vector metadata for spill storage")
endif()

if(NOT header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*Buffer\\*[ \t\r\n]*>[ \t\r\n]+spill_")
    message(FATAL_ERROR
        "MultiBuffer spill metadata should use ordinary std::vector<Buffer*>")
endif()
