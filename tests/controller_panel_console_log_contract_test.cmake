if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/app/bootstrap_panels.cpp"
    BOOTSTRAP_SOURCE)
file(READ
    "${SOURCE_DIR}/src/service/controller/controller.cpp"
    CONTROLLER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/service/controller/control.cpp"
    CONTROL_SOURCE)

if(NOT BOOTSTRAP_SOURCE MATCHES "panel configured name=" OR
   BOOTSTRAP_SOURCE MATCHES "panel ready name=")
    message(FATAL_ERROR
        "panel console output must distinguish configured from connected")
endif()

foreach(REQUIRED_STATUS
        [=[state=connecting]=]
        [=[state=missing]=]
        [=[state=unavailable phase=pull]=]
        [=[complete_sync ? "ready" : "degraded"]=]
        [=[inbound_started ? "ready" : "stopped"]=]
        [=[users={} rules={} pull={}s push={}s]=])
    string(FIND "${CONTROLLER_SOURCE}" "${REQUIRED_STATUS}" STATUS_POSITION)
    if(STATUS_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel console status is missing '${REQUIRED_STATUS}'")
    endif()
endforeach()

foreach(REQUIRED_REPORT
        [=[panel report name={} node={} state={}]=]
        [=[node_status={} traffic={} traffic_users={}]=]
        [=[online={} online_users={} illegal={} illegal_events={}]=]
        [=[report_ok ? "ok" : "degraded"]=]
        [=[return "idle"]=])
    string(FIND "${CONTROL_SOURCE}" "${REQUIRED_REPORT}" REPORT_POSITION)
    if(REPORT_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel console report is missing '${REQUIRED_REPORT}'")
    endif()
endforeach()
