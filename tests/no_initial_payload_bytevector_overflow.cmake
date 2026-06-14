file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/initial_payload.hpp" content)

if(content MATCHES "memory::ByteVector\\*[ \t\r\n]+overflow_")
    message(FATAL_ERROR
        "InitialPayload overflow must not use ByteVector storage; use Buffer/MultiBuffer ownership")
endif()

if(content MATCHES "EnsureOverflow\\(")
    message(FATAL_ERROR
        "InitialPayload must not allocate overflow through ByteVector helper storage")
endif()
