if(NOT DEFINED TEST_EXECUTABLE)
    message(FATAL_ERROR "TEST_EXECUTABLE is required")
endif()
execute_process(COMMAND "${TEST_EXECUTABLE}" --ready-fault
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR TIMEOUT 15)
if(RESULT STREQUAL "77")
    message(STATUS "SKIP: IPv6 unavailable; partial listener startup cannot be exercised")
    return()
endif()
if(NOT RESULT STREQUAL "0")
    message(FATAL_ERROR
        "post-spawn readiness allocation fault contract failed: result=${RESULT} output=${OUTPUT} error=${ERROR}")
endif()
message(STATUS "post-spawn readiness failure canceled and joined every listener")
