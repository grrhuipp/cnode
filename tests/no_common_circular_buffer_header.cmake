if(EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/common/circular_buffer.hpp")
    message(FATAL_ERROR
        "Unused CircularBuffer header must be removed; connection pending data should use Buffer/MultiBuffer ownership")
endif()
