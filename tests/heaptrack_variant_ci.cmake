file(READ "${PROJECT_SOURCE_DIR}/CMakeLists.txt" cmake_source)
file(READ "${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml" ci_workflow)

if(EXISTS "${PROJECT_SOURCE_DIR}/scripts/build-heaptrack.sh")
    message(FATAL_ERROR "scripts directory must only contain cnode.sh; heaptrack build stays in CI")
endif()

foreach(pattern IN ITEMS
        "option\\(CNODE_HEAPTRACK_BUILD"
        "CNODE_HEAPTRACK_BUILD requires a glibc toolchain, not musl"
        "CNODE_HEAPTRACK_BUILD AND USE_MIMALLOC"
        "set\\(USE_MIMALLOC OFF CACHE BOOL"
        "FORCE\\)"
        "set\\(BUILD_CHANNEL \"heaptrack\"\\)")
    if(NOT cmake_source MATCHES "${pattern}")
        message(FATAL_ERROR "CMake heaptrack variant guard is missing: ${pattern}")
    endif()
endforeach()

string(FIND "${ci_workflow}" "  build-glibc:" glibc_pos)
if(glibc_pos EQUAL -1)
    message(FATAL_ERROR "CI must define a dedicated glibc heaptrack job")
endif()

string(FIND "${ci_workflow}" "  publish-release:" publish_pos)
if(publish_pos EQUAL -1)
    string(LENGTH "${ci_workflow}" publish_pos)
endif()
math(EXPR glibc_len "${publish_pos} - ${glibc_pos}")
string(SUBSTRING "${ci_workflow}" ${glibc_pos} ${glibc_len} glibc_job)

foreach(pattern IN ITEMS
        "runs-on: ubuntu-24.04"
        "perl nasm"
        "-DCNODE_HEAPTRACK_BUILD=ON"
        "-DUSE_MIMALLOC=OFF"
        "name: cnode-glibc-assets"
        "cnode-linux-amd64-glibc")
    if(NOT glibc_job MATCHES "${pattern}")
        message(FATAL_ERROR "CI glibc heaptrack job is missing: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "container:"
        "image: alpine"
        "-DCMAKE_EXE_LINKER_FLAGS=\"-static\""
        "scripts/build-heaptrack.sh")
    if(glibc_job MATCHES "${pattern}")
        message(FATAL_ERROR "CI glibc heaptrack job must not use musl/static/script settings: ${pattern}")
    endif()
endforeach()

string(FIND "${ci_workflow}" "  build-musl:" musl_pos)
if(musl_pos EQUAL -1)
    message(FATAL_ERROR "CI must define a dedicated musl release job")
endif()
math(EXPR musl_len "${glibc_pos} - ${musl_pos}")
string(SUBSTRING "${ci_workflow}" ${musl_pos} ${musl_len} musl_job)
foreach(pattern IN ITEMS
        "image: alpine"
        "-DUSE_MIMALLOC=ON"
        "-DCMAKE_EXE_LINKER_FLAGS=\"-static\""
        "cnode-linux-amd64-musl")
    if(NOT musl_job MATCHES "${pattern}")
        message(FATAL_ERROR "CI musl job must keep the static mimalloc release variant: ${pattern}")
    endif()
endforeach()
