set(router_paths
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/router"
    "${PROJECT_SOURCE_DIR}/src/app/router"
)

foreach(path IN LISTS router_paths)
    file(GLOB_RECURSE files
        "${path}/*.hpp"
        "${path}/*.cpp"
        "${path}/*.ipp"
    )
    foreach(file IN LISTS files)
        file(READ "${file}" content)
        if(content MATCHES "#[ \t]*include[ \t]+[<\"]acppnode/app/relay")
            message(FATAL_ERROR "Router must not include relay headers: ${file}")
        endif()
        if(content MATCHES "DoRelay|DoUDPRelay|RelayTcp|RelayUdp|RelayResult")
            message(FATAL_ERROR "Router must not call or depend on relay APIs: ${file}")
        endif()
        if(content MATCHES "proxyman::|#[ \t]*include[ \t]+[<\"]acppnode/app/proxyman/")
            message(FATAL_ERROR "Router must not depend on proxyman concrete types: ${file}")
        endif()
    endforeach()
endforeach()
