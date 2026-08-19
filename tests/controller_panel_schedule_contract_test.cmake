if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/service/controller/controller.cpp"
    CONTROLLER_SOURCE)
file(READ
    "${SOURCE_DIR}/include/acppnode/common/defaults.hpp"
    DEFAULTS_SOURCE)

if(NOT DEFAULTS_SOURCE MATCHES
   "kPanelStatusLogInterval[ \t]*=[ \t]*60")
    message(FATAL_ERROR
        "panel status log interval must remain fixed at 60 seconds")
endif()

foreach(REQUIRED_TEXT
        "runPanelMonitors"
        "panelMonitor(panel, generation)"
        "generation == monitor_generation_"
        "config.PullInterval"
        "config.PushInterval"
        "auto next_push = Clock::time_point::max()"
        "committed_nodes_.contains(panel)"
        "const auto scheduled_push = now + interval(false)"
        "next_push = scheduled_push"
        "next_status"
        "defaults::kPanelStatusLogInterval"
        "logPanelStatus(panel)"
        "std::min({next_pull, next_push, next_status})"
        "PanelInterval")
    string(FIND "${CONTROLLER_SOURCE}" "${REQUIRED_TEXT}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel scheduler is missing '${REQUIRED_TEXT}'")
    endif()
endforeach()

if(CONTROLLER_SOURCE MATCHES
   "auto next_push[ \t]*=[ \t]*next_pull")
    message(FATAL_ERROR
        "the first panel report must wait one full push interval")
endif()

if(CONTROLLER_SOURCE MATCHES
   "expires_after\\(std::chrono::seconds\\(defaults::kPanelPullInterval\\)\\)")
    message(FATAL_ERROR
        "panel scheduling must not collapse back to one fixed pull interval")
endif()

foreach(FORBIDDEN_RETRY
        "kControllerSyncMaxAttempts"
        "kControllerSyncRetryBaseSeconds"
        "state=retrying"
        "attempts={}")
    string(FIND "${CONTROLLER_SOURCE}" "${FORBIDDEN_RETRY}" RETRY_POSITION)
    if(NOT RETRY_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel pulls must attempt once per configured interval; found '${FORBIDDEN_RETRY}'")
    endif()
endforeach()

if(DEFAULTS_SOURCE MATCHES "kControllerSync(MaxAttempts|RetryBaseSeconds)")
    message(FATAL_ERROR
        "single-attempt panel scheduling must not retain retry defaults")
endif()

string(REGEX MATCHALL "GetNodeInfo\\(\\)" NODE_PULL_CALLS
    "${CONTROLLER_SOURCE}")
list(LENGTH NODE_PULL_CALLS NODE_PULL_CALL_COUNT)
if(NOT NODE_PULL_CALL_COUNT EQUAL 1)
    message(FATAL_ERROR
        "panel scheduling must have exactly one node pull call path")
endif()

string(REGEX MATCHALL
    "userInfoMonitor\\(panel, tag\\)" PUSH_CALLS
    "${CONTROLLER_SOURCE}")
list(LENGTH PUSH_CALLS PUSH_CALL_COUNT)
if(NOT PUSH_CALL_COUNT EQUAL 1)
    message(FATAL_ERROR
        "status push must have one scheduler-owned call path")
endif()

string(REGEX MATCHALL
    "logPanelStatus\\(panel\\)" STATUS_LOG_CALLS
    "${CONTROLLER_SOURCE}")
list(LENGTH STATUS_LOG_CALLS STATUS_LOG_CALL_COUNT)
if(NOT STATUS_LOG_CALL_COUNT EQUAL 1)
    message(FATAL_ERROR
        "periodic panel status must have one scheduler-owned call path")
endif()

string(FIND "${CONTROLLER_SOURCE}"
    "Controller::Impl::nodeInfoMonitor" NODE_MONITOR_BEGIN)
string(FIND "${CONTROLLER_SOURCE}"
    "}  // namespace acpp" NODE_MONITOR_END)
if(NODE_MONITOR_BEGIN EQUAL -1 OR NODE_MONITOR_END EQUAL -1 OR
   NOT NODE_MONITOR_BEGIN LESS NODE_MONITOR_END)
    message(FATAL_ERROR "could not isolate nodeInfoMonitor")
endif()
math(EXPR NODE_MONITOR_LENGTH
    "${NODE_MONITOR_END} - ${NODE_MONITOR_BEGIN}")
string(SUBSTRING "${CONTROLLER_SOURCE}"
    ${NODE_MONITOR_BEGIN} ${NODE_MONITOR_LENGTH} NODE_MONITOR_SOURCE)
if(NODE_MONITOR_SOURCE MATCHES "userInfoMonitor")
    message(FATAL_ERROR
        "node pulls must not own status push scheduling")
endif()
