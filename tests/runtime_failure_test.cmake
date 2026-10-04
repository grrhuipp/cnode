if(NOT DEFINED TEST_EXECUTABLE)
    message(FATAL_ERROR "TEST_EXECUTABLE is required")
endif()
execute_process(COMMAND "${TEST_EXECUTABLE}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR TIMEOUT 5)
if(NOT RESULT STREQUAL "1" OR
   NOT ERROR MATCHES "runtime failed phase=udp-receive error=registered socket receive loop stopped status=forced")
    message(FATAL_ERROR "fatal runtime contract failed: result=${RESULT} output=${OUTPUT} error=${ERROR}")
endif()
