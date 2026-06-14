set(dispatcher_paths
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/dispatcher"
    "${PROJECT_SOURCE_DIR}/src/app/dispatcher"
)

foreach(path IN LISTS dispatcher_paths)
    file(GLOB_RECURSE files
        "${path}/*.hpp"
        "${path}/*.cpp"
        "${path}/*.ipp"
    )
    foreach(file IN LISTS files)
        file(READ "${file}" content)
        if(content MATCHES "#[ \t]*include[ \t]+[<\"]acppnode/proxy/(vmess|trojan|shadowsocks|anytls|freedom|blackhole)/")
            message(FATAL_ERROR "Dispatcher includes concrete protocol implementation in ${file}")
        endif()
    endforeach()
endforeach()
