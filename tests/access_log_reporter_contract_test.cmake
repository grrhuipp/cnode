if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/infra/access_log_reporter.cpp"
    REPORTER_SOURCE)

string(FIND "${REPORTER_SOURCE}" "auto spool = std::make_unique<Spool>(spool_path_)"
       SPOOL_INITIALIZE_POSITION)
string(FIND "${REPORTER_SOURCE}" "thread_ = std::thread([this] { Run(); })"
       THREAD_START_POSITION)
if(SPOOL_INITIALIZE_POSITION EQUAL -1 OR THREAD_START_POSITION EQUAL -1 OR
   NOT SPOOL_INITIALIZE_POSITION LESS THREAD_START_POSITION)
    message(FATAL_ERROR
        "access-log durable spool must initialize before the reporter thread starts")
endif()
if(NOT REPORTER_SOURCE MATCHES
       "if [(][!]spool->Initialize[(][)][)]" OR
   NOT REPORTER_SOURCE MATCHES
       "Spool& spool = [*]spool_" OR
   REPORTER_SOURCE MATCHES
       "const bool spool_ready = spool[.]Initialize[(][)]")
    message(FATAL_ERROR
        "access-log Initialize must fail closed and hand one prepared spool to Run")
endif()
