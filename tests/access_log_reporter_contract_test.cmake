if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/infra/access_log_reporter.cpp"
    REPORTER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/access_log_session.cpp"
    SESSION_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/proxyman/inbound/handler.cpp"
    INBOUND_HANDLER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp"
    DISPATCHER_SOURCE)

string(FIND "${REPORTER_SOURCE}" "auto spool = std::make_unique<Spool>(spool_path_)"
       SPOOL_INITIALIZE_POSITION)
string(FIND "${REPORTER_SOURCE}" "thread_ = std::thread([this] { Run(); })"
       THREAD_START_POSITION)
if(SPOOL_INITIALIZE_POSITION EQUAL -1 OR THREAD_START_POSITION EQUAL -1 OR
   NOT SPOOL_INITIALIZE_POSITION LESS THREAD_START_POSITION)
    message(FATAL_ERROR
        "access-log durable spool must initialize before the reporter thread starts")
endif()

if(NOT DISPATCHER_SOURCE MATCHES
       "result = co_await DispatchPreparedLink" OR
   NOT DISPATCHER_SOURCE MATCHES
       "dispatcher request exception" OR
   NOT DISPATCHER_SOURCE MATCHES
       "access_log[.]Complete[(]result[)]")
    message(FATAL_ERROR
        "Dispatcher must normalize exceptions before the shared access-log terminal boundary")
endif()

if(NOT SESSION_SOURCE MATCHES
       "AccessLogSession::Fail[(]ErrorCode error_code[)]" OR
   NOT INBOUND_HANDLER_SOURCE MATCHES
       "access_log[.]Fail[(]build_result[.]error[(][)][)]" OR
   NOT INBOUND_HANDLER_SOURCE MATCHES
       "access_log[.]Fail[(]ErrorCode::INTERNAL[)]")
    message(FATAL_ERROR
        "pre-dispatch transport and protocol failures must reach the access-log terminal path")
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

if(REPORTER_SOURCE MATCHES "QuarantineFront" OR
   REPORTER_SOURCE MATCHES "replace_extension[(]\"[.]bad\"[)]" OR
   REPORTER_SOURCE MATCHES "ignoring malformed spool file" OR
   REPORTER_SOURCE MATCHES "ignoring invalid spool file")
    message(FATAL_ERROR
        "access-log spool must not abandon invalid files outside its capacity accounting")
endif()
if(NOT REPORTER_SOURCE MATCHES
       "bool DiscardFront[(][)]" OR
   NOT REPORTER_SOURCE MATCHES
       "if [(]spool[.]DiscardFront[(][)][)]")
    message(FATAL_ERROR
        "unreadable batches must remain owned until their file is removed")
endif()

if(NOT REPORTER_SOURCE MATCHES
       "else if [(]sent[.]status == 400[)]" OR
   NOT REPORTER_SOURCE MATCHES
       "if [(]spool[.]DiscardFront[(][)][)]")
    message(FATAL_ERROR
        "permanently invalid service batches must not block later protocol logs")
endif()

if(SESSION_SOURCE MATCHES
       "if [(]result[.]error != ErrorCode::OK[)]" OR
   SESSION_SOURCE MATCHES
       "AccessLogSession::Cancel" OR
   NOT SESSION_SOURCE MATCHES
       "error_code_ = result[.]error" OR
   NOT SESSION_SOURCE MATCHES
       "AccessLogSession::Suppress")
    message(FATAL_ERROR
        "logical request failures must be reported; only container sessions may be suppressed")
endif()

string(FIND "${SESSION_SOURCE}"
       "Reporter::Instance().Submit(BuildAccessLogEvent"
       SESSION_SUBMIT_POSITION)
string(FIND "${SESSION_SOURCE}"
       "ctx_->access_event_submitted = true"
       SESSION_SUBMITTED_POSITION)
if(SESSION_SUBMIT_POSITION EQUAL -1 OR SESSION_SUBMITTED_POSITION EQUAL -1 OR
   NOT SESSION_SUBMIT_POSITION LESS SESSION_SUBMITTED_POSITION OR
   NOT SESSION_SOURCE MATCHES
       "if [(]accesslog::Reporter::Instance[(][)][.]Submit")
    message(FATAL_ERROR
        "an access event may become idempotent only after reporter admission")
endif()
