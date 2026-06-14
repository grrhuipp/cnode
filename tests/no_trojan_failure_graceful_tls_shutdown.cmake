set(INBOUND_FILE "${PROJECT_SOURCE_DIR}/src/proxy/trojan/inbound/trojan_inbound.cpp")
set(OUTBOUND_FILE "${PROJECT_SOURCE_DIR}/src/proxy/trojan/outbound/trojan_outbound.cpp")

foreach(file IN ITEMS "${INBOUND_FILE}" "${OUTBOUND_FILE}")
    if(NOT EXISTS "${file}")
        message(FATAL_ERROR "missing Trojan implementation: ${file}")
    endif()
endforeach()

file(READ "${INBOUND_FILE}" inbound_source)
file(READ "${OUTBOUND_FILE}" outbound_source)

string(FIND "${inbound_source}" "auto fail_abortive" inbound_helper_pos)
string(FIND "${inbound_source}" "stream->CloseAbortive();" inbound_close_pos)
if(inbound_helper_pos EQUAL -1 OR inbound_close_pos EQUAL -1 OR inbound_close_pos LESS inbound_helper_pos)
    message(FATAL_ERROR
        "Trojan inbound handshake/auth failure paths must use abortive close")
endif()

foreach(pattern IN ITEMS
    "co_return fail(read_result.error());"
    "co_return fail(ErrorCode::BLOCKED);"
    "co_return fail(ErrorCode::PROTOCOL_DECODE_FAILED);"
    "co_return fail(ErrorCode::PROTOCOL_AUTH_FAILED);")
    string(FIND "${inbound_source}" "${pattern}" bad_pos)
    if(NOT bad_pos EQUAL -1)
        message(FATAL_ERROR
            "Trojan inbound failure path bypasses abortive close: ${pattern}")
    endif()
endforeach()

string(FIND "${outbound_source}" "auto fail_abortive" outbound_helper_pos)
string(FIND "${outbound_source}" "stream->CloseAbortive();" outbound_close_pos)
if(outbound_helper_pos EQUAL -1 OR outbound_close_pos EQUAL -1 OR outbound_close_pos LESS outbound_helper_pos)
    message(FATAL_ERROR
        "Trojan outbound handshake failure paths must use abortive close")
endif()

if(outbound_source MATCHES "stream->[ \t\r\n]*Cancel\\([ \t\r\n]*\\)[ \t\r\n]*;[ \t\r\n]*co_return[ \t\r\n]+std::unexpected")
    message(FATAL_ERROR
        "Trojan outbound failure paths must not cancel-only before returning errors")
endif()
