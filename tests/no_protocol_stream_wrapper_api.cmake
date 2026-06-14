set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(SCAN_DIRS
    "${ROOT}/include/acppnode/proxy"
    "${ROOT}/src/proxy"
)

set(FORBIDDEN_PATTERNS
    "\\bSsServerAsyncStream\\b"
    "\\bSsClientAsyncStream\\b"
    "\\bVMess(Stream|AsyncStream|StreamWrapper)\\b"
    "\\bTrojan(Stream|AsyncStream|StreamWrapper)\\b"
    "\\bShadowsocks(Stream|AsyncStream|StreamWrapper)\\b"
    "\\b[A-Za-z0-9_]*(StreamWrapper|WrapperStream)\\b"
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
                    "protocol stream wrapper API remains in ${file}: ${pattern}")
            endif()
        endforeach()
    endforeach()
endforeach()
