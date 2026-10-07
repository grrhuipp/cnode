if(NOT DEFINED TEST_EXECUTABLE OR NOT DEFINED SCHEDULE_INDEX)
    message(FATAL_ERROR "TEST_EXECUTABLE and SCHEDULE_INDEX are required")
endif()
execute_process(COMMAND "${TEST_EXECUTABLE}" --maintenance-fault "${SCHEDULE_INDEX}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR TIMEOUT 15)
if(NOT RESULT STREQUAL "1" OR
   NOT ERROR MATCHES "udp-listener-fault stage=udp-maintenance index=${SCHEDULE_INDEX}" OR
   NOT ERROR MATCHES "udp-listener-fault consumed=pmr rejected=1" OR
   NOT ERROR MATCHES "runtime failed phase=udp-maintenance" OR
   (SCHEDULE_INDEX EQUAL 1 AND NOT ERROR MATCHES "udp-maintenance-rearm begun=1"))
    message(FATAL_ERROR "real Worker maintenance fault contract failed: result=${RESULT} output=${OUTPUT} error=${ERROR}")
endif()
message(STATUS "real Worker UDP maintenance allocation fault consumed; index=${SCHEDULE_INDEX}, fatal exit=${RESULT}")
