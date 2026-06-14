file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/relay.hpp" relay_header)

string(FIND "${relay_header}" "if (mb.empty())" empty_branch_pos)
string(FIND "${relay_header}" "ConsumeRelayTimeoutSignals(from_control, to_control)" timeout_signal_pos)
string(FIND "${relay_header}" "if (peer_state.eof)" peer_eof_pos)

if(empty_branch_pos EQUAL -1 OR timeout_signal_pos EQUAL -1 OR peer_eof_pos EQUAL -1)
    message(FATAL_ERROR "relay half-close empty-read branch must be recognizable")
endif()

if(NOT (empty_branch_pos LESS timeout_signal_pos AND timeout_signal_pos LESS peer_eof_pos))
    message(FATAL_ERROR
        "relay must consume read/write/idle/phase timeout signals before treating an empty read as EOF")
endif()

string(FIND "${relay_header}" "if (mb.empty()) {\n                if (ConsumeReadSideTimeoutSignal(from_control))" old_timeout_pos)
if(NOT old_timeout_pos EQUAL -1)
    message(FATAL_ERROR "relay must not ignore phase deadlines in the empty-read branch")
endif()
