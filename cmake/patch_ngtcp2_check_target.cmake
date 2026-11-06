if(NOT DEFINED NGTCP2_SOURCE_DIR)
    message(FATAL_ERROR "NGTCP2_SOURCE_DIR is required")
endif()

set(cmake_file "${NGTCP2_SOURCE_DIR}/CMakeLists.txt")
file(READ "${cmake_file}" contents)

set(original "add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})")
set(replacement "if(NOT TARGET check)\n  add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})\nendif()")

if(contents MATCHES "if\\(NOT TARGET check\\)")
    message(STATUS "ngtcp2 check-target patch already applied")
    return()
endif()

string(FIND "${contents}" "${original}" location)
if(location EQUAL -1)
    message(FATAL_ERROR "ngtcp2 check-target declaration changed upstream")
endif()

string(REPLACE "${original}" "${replacement}" contents "${contents}")
file(WRITE "${cmake_file}" "${contents}")
message(STATUS "Applied ngtcp2 check-target patch")
