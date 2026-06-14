set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(SCAN_DIRS
    "${ROOT}/include/acppnode/app/dispatcher"
    "${ROOT}/src/app/dispatcher"
)

set(FORBIDDEN_PATTERNS
    "#include[ \t]+[<\"]acppnode/app/relay\\.hpp[>\"]"
    "#include[ \t]+[<\"]acppnode/common/mux/mux_relay\\.hpp[>\"]"
    "\\bDoRelay\\b"
    "\\bDoMuxRelay\\b"
    "\\bDoUDPRelay\\b"
)

foreach(dir IN LISTS SCAN_DIRS)
    if(NOT IS_DIRECTORY "${dir}")
        continue()
    endif()

    file(GLOB_RECURSE files
        "${dir}/*.hpp"
        "${dir}/*.cpp"
    )

    foreach(file IN LISTS files)
        file(READ "${file}" content)
        foreach(pattern IN LISTS FORBIDDEN_PATTERNS)
            if(content MATCHES "${pattern}")
                message(FATAL_ERROR
                    "dispatcher must not directly include or call relay APIs: ${file} matches ${pattern}")
            endif()
        endforeach()
    endforeach()
endforeach()
