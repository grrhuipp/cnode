if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/service/controller/controller.cpp"
    CONTROLLER_SOURCE)

foreach(REQUIRED_TEXT
        "runPanelMonitors"
        "panelMonitor(panel, generation)"
        "generation == monitor_generation_"
        "config.PullInterval"
        "config.PushInterval"
        "PanelInterval")
    string(FIND "${CONTROLLER_SOURCE}" "${REQUIRED_TEXT}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel scheduler is missing '${REQUIRED_TEXT}'")
    endif()
endforeach()

if(CONTROLLER_SOURCE MATCHES
   "expires_after\\(std::chrono::seconds\\(defaults::kPanelPullInterval\\)\\)")
    message(FATAL_ERROR
        "panel scheduling must not collapse back to one fixed pull interval")
endif()

string(REGEX MATCHALL
    "userInfoMonitor\\(panel, tag, protocol\\)" PUSH_CALLS
    "${CONTROLLER_SOURCE}")
list(LENGTH PUSH_CALLS PUSH_CALL_COUNT)
if(NOT PUSH_CALL_COUNT EQUAL 1)
    message(FATAL_ERROR
        "status push must have one scheduler-owned call path")
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
