file(READ "${PROJECT_SOURCE_DIR}/src/common/session.cpp" session_source)

if(NOT session_source MATCHES "kTimestampCacheSize[ \t\r\n]*=[ \t\r\n]*8")
    message(FATAL_ERROR "access-log timestamp formatting must keep a small per-thread second cache")
endif()

if(NOT session_source MATCHES "thread_local[ \t\r\n]+std::array[ \t\r\n]*<[ \t\r\n]*CachedTimestamp")
    message(FATAL_ERROR "FormatTimestamp must use a thread-local cache to keep strftime out of the access-log hot path")
endif()

if(NOT session_source MATCHES "if[ \t\r\n]*\\([ \t\r\n]*entry\\.sec[ \t\r\n]*==[ \t\r\n]*sec[ \t\r\n]*\\)[ \t\r\n]*\\{[ \t\r\n]*return[ \t\r\n]+entry\\.value")
    message(FATAL_ERROR "FormatTimestamp must return cached values before calling FormatLocalTime")
endif()
