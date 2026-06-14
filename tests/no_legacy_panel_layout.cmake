set(forbidden_paths
    "${PROJECT_SOURCE_DIR}/include/acppnode/api/newV2board"
    "${PROJECT_SOURCE_DIR}/src/api/newV2board"
)

foreach(path IN LISTS forbidden_paths)
    if(EXISTS "${path}")
        message(FATAL_ERROR "Legacy panel layout must not remain: ${path}")
    endif()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/CMakeLists.txt" cmake_lists)
if(cmake_lists MATCHES "api/newV2board|api\\\\newV2board")
    message(FATAL_ERROR "CMakeLists.txt must not reference api/newV2board")
endif()
