if(NOT DEFINED TEST_EXECUTABLE OR NOT DEFINED SPAWN_INDEX)
    message(FATAL_ERROR "TEST_EXECUTABLE and SPAWN_INDEX are required")
endif()
execute_process(COMMAND "${TEST_EXECUTABLE}" --spawn-fault "${SPAWN_INDEX}"
    RESULT_VARIABLE RESULT OUTPUT_VARIABLE OUTPUT ERROR_VARIABLE ERROR TIMEOUT 15)
if(RESULT STREQUAL "77")
    message(STATUS "SKIP: IPv6 unavailable; partial listener startup cannot be exercised")
    return()
endif()
if(NOT RESULT STREQUAL "1" OR
   NOT ERROR MATCHES "udp-listener-fault stage=spawn index=${SPAWN_INDEX}" OR
   NOT ERROR MATCHES "udp-listener-fault consumed=std-new" OR
   NOT ERROR MATCHES "runtime failed phase=udp-listener-start" OR
   (SPAWN_INDEX EQUAL 1 AND NOT ERROR MATCHES "udp-listener-runtime spawn-started index=0"))
    message(FATAL_ERROR "real Worker spawn fault contract failed: result=${RESULT} output=${OUTPUT} error=${ERROR}")
endif()
message(STATUS "real Worker co_spawn allocation fault consumed; index=${SPAWN_INDEX}, fatal exit=${RESULT}")
