if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/infra/access_log_reporter.cpp"
    REPORTER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/infra/log.cpp"
    LOG_SOURCE)

if(NOT REPORTER_SOURCE MATCHES
       "kEventQueueCapacity = 8 [*] 1024" OR
   NOT REPORTER_SOURCE MATCHES
       "queue_[(]kEventQueueCapacity[)]" OR
   NOT REPORTER_SOURCE MATCHES
       "previous >= kEventQueueCapacity" OR
   NOT REPORTER_SOURCE MATCHES
       "queue_[.]try_enqueue")
    message(FATAL_ERROR
        "structured log admission must keep its 8K preallocated, non-allocating queue budget")
endif()

if(NOT LOG_SOURCE MATCHES
       "kAsyncLogQueueCapacity = 8 [*] 1024" OR
   NOT LOG_SOURCE MATCHES
       "queue_[(]kAsyncLogQueueCapacity[)]" OR
   NOT LOG_SOURCE MATCHES
       "queue_[.]try_enqueue")
    message(FATAL_ERROR
        "local async logging must keep its 8K preallocated, non-allocating queue budget")
endif()
