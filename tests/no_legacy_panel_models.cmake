set(forbidden_paths
    "${PROJECT_SOURCE_DIR}/include/acppnode/api/newV2board"
    "${PROJECT_SOURCE_DIR}/src/api/newV2board"
)

foreach(path IN LISTS forbidden_paths)
    if(EXISTS "${path}")
        message(FATAL_ERROR "Legacy panel model path remains: ${path}")
    endif()
endforeach()

set(scan_paths
    "${PROJECT_SOURCE_DIR}/include/acppnode/api"
    "${PROJECT_SOURCE_DIR}/src/api"
    "${PROJECT_SOURCE_DIR}/src/app/bootstrap_panels.cpp"
)

foreach(path IN LISTS scan_paths)
    if(IS_DIRECTORY "${path}")
        file(GLOB_RECURSE files "${path}/*.hpp" "${path}/*.cpp")
    else()
        set(files "${path}")
    endif()

    foreach(file IN LISTS files)
        file(READ "${file}" content)
        if(content MATCHES "new[Vv]2board|NewV2board|api::newV2board")
            message(FATAL_ERROR "Legacy panel model name remains in ${file}")
        endif()
    endforeach()
endforeach()
