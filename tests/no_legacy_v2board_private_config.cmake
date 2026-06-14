set(scan_paths
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/CMakeLists.txt"
)

foreach(path IN LISTS scan_paths)
    if(IS_DIRECTORY "${path}")
        file(GLOB_RECURSE files
            "${path}/*.hpp"
            "${path}/*.cpp"
            "${path}/*.ipp"
            "${path}/*.cmake"
        )
    else()
        set(files "${path}")
    endif()

    foreach(file IN LISTS files)
        file(READ "${file}" content)
        if(content MATCHES "new[Vv]2board|NewV2board")
            message(FATAL_ERROR "Legacy V2Board private naming remains in ${file}")
        endif()
    endforeach()
endforeach()
