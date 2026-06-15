file(READ "${PROJECT_SOURCE_DIR}/src/infra/log.cpp" log_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/infra/log.hpp" log_header)

foreach(pattern IN ITEMS
        "moodycamel::ConcurrentQueue[ \t\r\n]*<[ \t\r\n]*LogRecord[ \t\r\n]*>"
        "thread_local[ \t\r\n]+moodycamel::ProducerToken"
        "kAsyncLogQueueSize[ \t\r\n]*=[ \t\r\n]*65536"
        "queue_\\.try_enqueue"
        "queue_\\.try_dequeue")
    if(NOT log_source MATCHES "${pattern}")
        message(FATAL_ERROR "log backend must keep the lock-free async queue hot path: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "std::ofstream[ \t\r\n]+g_error_file"
        "std::ofstream[ \t\r\n]+g_access_file"
        "std::mutex[ \t\r\n]+g_error_mutex"
        "std::mutex[ \t\r\n]+g_access_mutex"
        "spdlog::")
    if(log_source MATCHES "${pattern}" OR log_header MATCHES "${pattern}")
        message(FATAL_ERROR "worker log path must not regress to synchronous file locks or spdlog queues: ${pattern}")
    endif()
endforeach()

if(log_source MATCHES "void Log::WriteApp\\([^\\)]*\\)[ \t\r\n]*\\{[^}]*std::lock_guard")
    message(FATAL_ERROR "WriteApp must not take a mutex on worker threads")
endif()

if(log_source MATCHES "void Log::WriteAccess\\([^\\)]*\\)[ \t\r\n]*\\{[^}]*std::lock_guard")
    message(FATAL_ERROR "WriteAccess must not take a mutex on worker threads")
endif()

foreach(pattern IN ITEMS
        "std::atomic<LogLevel>[ \t\r\n]+min_level_"
        "std::atomic_bool[ \t\r\n]+initialized_"
        "LOG_INFO\\(fmt_str, \\.\\.\\.\\)[^#]*ShouldLog\\(acpp::LogLevel::INFO\\)[^#]*std::format"
        "LOG_ACCESS\\(msg\\)[^#]*ShouldLog\\(acpp::LogLevel::INFO\\)[^#]*WriteAccess\\(\\(msg\\)\\)"
        "LOG_ACCESS_FMT\\(fmt_str, \\.\\.\\.\\)[^#]*ShouldLog\\(acpp::LogLevel::INFO\\)[^#]*std::format"
        "LOG_CONN_FAIL\\(fmt_str, \\.\\.\\.\\)[^#]*ShouldLog\\(acpp::LogLevel::WARN\\)[^#]*std::format")
    if(NOT log_header MATCHES "${pattern}")
        message(FATAL_ERROR "log macros must keep runtime-level filtering before formatting: ${pattern}")
    endif()
endforeach()

if(NOT log_source MATCHES "min_level_\\.load\\(std::memory_order_relaxed\\)[ \t\r\n]*==[ \t\r\n]*LogLevel::NONE")
    message(FATAL_ERROR "WriteAccess must only suppress the NONE level; per-message runtime levels belong in macros")
endif()
