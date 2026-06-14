set(scan_paths
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src"
)

foreach(path IN LISTS scan_paths)
    file(GLOB_RECURSE files
        "${path}/*.hpp"
        "${path}/*.cpp"
        "${path}/*.ipp"
    )
    foreach(file IN LISTS files)
        file(READ "${file}" content)
        if(content MATCHES "ParsedAction|parsed[ _-]action|action[ _-]handoff|handoff[ _-]action")
            message(FATAL_ERROR "Parsed action handoff remains in ${file}")
        endif()
    endforeach()
endforeach()
