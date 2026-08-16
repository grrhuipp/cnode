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
file(READ
    "${SOURCE_DIR}/src/app/access_log_event.cpp"
    EVENT_SOURCE)
file(READ
    "${SOURCE_DIR}/src/transport/internet/tcp_stream.cpp"
    TCP_STREAM_SOURCE)
file(READ
    "${SOURCE_DIR}/src/transport/internet/tls_stream.cpp"
    TLS_STREAM_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/common/read_prefix_capture.hpp"
    READ_CAPTURE_SOURCE)

string(FIND "${REPORTER_SOURCE}" "auto access_spool = std::make_unique<Spool>(access_spool_path_)"
       SPOOL_INITIALIZE_POSITION)
string(FIND "${REPORTER_SOURCE}" "thread_ = std::thread([this] { Run(); })"
       THREAD_START_POSITION)
if(SPOOL_INITIALIZE_POSITION EQUAL -1 OR THREAD_START_POSITION EQUAL -1 OR
   NOT SPOOL_INITIALIZE_POSITION LESS THREAD_START_POSITION)
    message(FATAL_ERROR
        "access-log durable spool must initialize before the reporter thread starts")
endif()

if(NOT REPORTER_SOURCE MATCHES
       "kMaxSpoolBytes = 128ULL [*] 1024 [*] 1024" OR
   NOT REPORTER_SOURCE MATCHES
       "while [(]bytes_ > kMaxSpoolBytes && !entries_[.]empty[(][)][)]" OR
   NOT REPORTER_SOURCE MATCHES
       "while [(]bytes_ [+] payload[.]size[(][)] > kMaxSpoolBytes && !entries_[.]empty[(][)][)]")
    message(FATAL_ERROR
        "each access/error spool must evict oldest batches at the 128 MiB hard limit")
endif()

if(INBOUND_HANDLER_SOURCE MATCHES
       "access_log[.]Fail[(]ErrorCode::RESOURCE_EXHAUSTED[)]" OR
   NOT INBOUND_HANDLER_SOURCE MATCHES
       "access_log[.]Fail[(]ErrorCode::CONNECTION_LIMITED[)]" OR
   NOT EVENT_SOURCE MATCHES
       "case ErrorCode::CONNECTION_LIMITED:")
    message(FATAL_ERROR
        "connection admission limits must be reported as rejected, not failed")
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

if(NOT SESSION_SOURCE MATCHES
       "result[.]close_side_known" OR
   NOT SESSION_SOURCE MATCHES
       "result[.]client_closed_first")
    message(FATAL_ERROR
        "relay failures with a known closer must retain their access-log close side")
endif()
if(NOT REPORTER_SOURCE MATCHES
       "access_spool->Initialize[(][)]" OR
   NOT REPORTER_SOURCE MATCHES
       "error_spool->Initialize[(][)]" OR
   NOT REPORTER_SOURCE MATCHES
       "Spool& access_spool = [*]access_spool_" OR
   NOT REPORTER_SOURCE MATCHES
       "Spool& error_spool = [*]error_spool_" OR
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
       "if [(]stream[.]spool->DiscardFront[(][)][)]")
    message(FATAL_ERROR
        "unreadable batches must remain owned until their file is removed")
endif()

if(NOT REPORTER_SOURCE MATCHES
       "else if [(]sent[.]status == 400[)]" OR
   NOT REPORTER_SOURCE MATCHES
       "if [(]stream[.]spool->DiscardFront[(][)][)]")
    message(FATAL_ERROR
        "permanently invalid service batches must not block later protocol logs")
endif()

if(SESSION_SOURCE MATCHES
       "ctx_->inbound[.]user_id != 0" OR
   SESSION_SOURCE MATCHES
       "ctx_->outbound[.]target[.]IsValid[(][)]" OR
   NOT SESSION_SOURCE MATCHES
       "error_code_ = result[.]error" OR
   NOT SESSION_SOURCE MATCHES
       "AccessLogSession::Suppress")
    message(FATAL_ERROR
        "pre-authentication and targetless failures must be reported; only container events may be suppressed")
endif()

if(NOT REPORTER_SOURCE MATCHES "kAccessBatchTarget" OR
   NOT REPORTER_SOURCE MATCHES "kErrorBatchTarget" OR
   NOT REPORTER_SOURCE MATCHES
       "event[.]error_code == ErrorCode::OK" OR
   NOT EVENT_SOURCE MATCHES "raw_packet")
    message(FATAL_ERROR
        "normal access and error/security events must use separate durable streams")
endif()

if(NOT INBOUND_HANDLER_SOURCE MATCHES "SetReadPrefixCapture" OR
   NOT TCP_STREAM_SOURCE MATCHES "CaptureReadPrefix" OR
   NOT TLS_STREAM_SOURCE MATCHES "CaptureReadPrefix" OR
   NOT DISPATCHER_SOURCE MATCHES "read_prefix_capture[.]reset[(][)]" OR
   NOT READ_CAPTURE_SOURCE MATCHES "8U [*] 1024U")
    message(FATAL_ERROR
        "pre-dispatch TCP/TLS raw packet capture must remain bounded and be released after authentication")
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
