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

string(FIND "${BOOTSTRAP_SOURCE}"
    "Panel {}: configured |" CONFIGURED_POSITION)
string(FIND "${BOOTSTRAP_SOURCE}"
    "Panel {}: ready" READY_POSITION)
if(CONFIGURED_POSITION EQUAL -1 OR NOT READY_POSITION EQUAL -1)
    message(FATAL_ERROR
        "panel console output must distinguish configured from connected")
endif()

foreach(REQUIRED_STATUS
        [=[status: connecting]=]
        [=[sync: missing]=]
        [=[sync: unavailable | pull]=]
        [=[case PanelState::Ready: return "ready"]=]
        [=[case PanelState::Degraded: return "degraded"]=]
        [=[status: {} | inbound {}]=]
        [=[users {} | rules {}]=]
        [=[pull/push {}s/{}s]=])
    string(FIND "${CONTROLLER_SOURCE}" "${REQUIRED_STATUS}" STATUS_POSITION)
    if(STATUS_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel console status is missing '${REQUIRED_STATUS}'")
    endif()
endforeach()

foreach(REQUIRED_REPORT
        [=[Panel {}/{} report: {}]=]
        [=[node {} | traffic {}/{}]=]
        [=[online {}/{}]=]
        [=[devices {}]=]
        [=[illegal {}/{}]=]
        [=[report_ok ? "ok" : "degraded"]=]
        [=[return "idle"]=])
    string(FIND "${CONTROL_SOURCE}" "${REQUIRED_REPORT}" REPORT_POSITION)
    if(REPORT_POSITION EQUAL -1)
        message(FATAL_ERROR
            "panel console report is missing '${REQUIRED_REPORT}'")
    endif()
endforeach()
