if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/service/controller/control.cpp"
    CONTROL_SOURCE)
file(READ
    "${SOURCE_DIR}/src/api/v2board/v2board.cpp"
    V2BOARD_SOURCE)

foreach(REQUIRED_CONTROL
        "GetOnlineSnapshot(tag)"
        "online.user_count"
        "online.entries.size()"
        "ns.online_count = traffic_data.size()"
        "ReportUserTraffic(traffic_data)"
        "ReportNodeOnlineUsers(online.entries)")
    string(FIND "${CONTROL_SOURCE}" "${REQUIRED_CONTROL}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "controller online reporting is missing '${REQUIRED_CONTROL}'")
    endif()
endforeach()

if(CONTROL_SOURCE MATCHES "if[ \t\r\n]*\\([ \t\r\n]*!traffic_data[.]empty[ \t\r\n]*\\)[ \t\r\n]*\\{[\t\r\n ]*try[\t\r\n ]*\\{[\t\r\n ]*traffic_ok")
    message(FATAL_ERROR
        "zero traffic users must still be pushed to clear panel state")
endif()

string(FIND "${V2BOARD_SOURCE}"
    "APIClient::Impl::ReportNodeOnlineUsers" REPORT_BEGIN)
string(FIND "${V2BOARD_SOURCE}"
    "APIClient::Impl::GetNodeRule" REPORT_END)
if(REPORT_BEGIN EQUAL -1 OR REPORT_END EQUAL -1 OR
   NOT REPORT_BEGIN LESS REPORT_END)
    message(FATAL_ERROR "could not isolate V2Board online reporting")
endif()
math(EXPR REPORT_LENGTH "${REPORT_END} - ${REPORT_BEGIN}")
string(SUBSTRING "${V2BOARD_SOURCE}"
    ${REPORT_BEGIN} ${REPORT_LENGTH} REPORT_SOURCE)

foreach(REQUIRED_REPORT
        "report.alive_body"
        "/api/v1/server/UniProxy/alive")
    string(FIND "${REPORT_SOURCE}" "${REQUIRED_REPORT}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR
            "V2Board online reporting is missing '${REQUIRED_REPORT}'")
    endif()
endforeach()

if(REPORT_SOURCE MATCHES "/api/v1/server/UniProxy/push")
    message(FATAL_ERROR
        "V2Board device reporting must not overwrite traffic-based online counts")
endif()

string(FIND "${V2BOARD_SOURCE}"
    "APIClient::Impl::ReportUserTraffic" TRAFFIC_BEGIN)
if(TRAFFIC_BEGIN EQUAL -1 OR NOT TRAFFIC_BEGIN LESS REPORT_BEGIN)
    message(FATAL_ERROR "could not isolate V2Board traffic reporting")
endif()
math(EXPR TRAFFIC_LENGTH "${REPORT_BEGIN} - ${TRAFFIC_BEGIN}")
string(SUBSTRING "${V2BOARD_SOURCE}"
    ${TRAFFIC_BEGIN} ${TRAFFIC_LENGTH} TRAFFIC_SOURCE)
if(NOT TRAFFIC_SOURCE MATCHES "/api/v1/server/UniProxy/push")
    message(FATAL_ERROR "V2Board traffic reporting must use /push")
endif()
if(TRAFFIC_SOURCE MATCHES "if[ \t\r\n]*\\([ \t\r\n]*data[.]empty")
    message(FATAL_ERROR
        "V2Board traffic reporting must post an empty object to clear zero")
endif()
