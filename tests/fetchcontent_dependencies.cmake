file(READ "${PROJECT_SOURCE_DIR}/CMakeLists.txt" cmake_source)
file(READ "${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml" ci_workflow)
file(READ "${PROJECT_SOURCE_DIR}/README.md" readme)
file(READ "${PROJECT_SOURCE_DIR}/.gitignore" gitignore)

if(EXISTS "${PROJECT_SOURCE_DIR}/vcpkg.json")
    message(FATAL_ERROR "vcpkg manifest must not reappear; dependencies are provided by CMake FetchContent")
endif()

if(EXISTS "${PROJECT_SOURCE_DIR}/scripts/build-heaptrack.sh")
    message(FATAL_ERROR "scripts directory must only contain cnode.sh; heaptrack build stays in CI")
endif()

foreach(content_name IN ITEMS cmake_source ci_workflow readme gitignore)
    if("${${content_name}}" MATCHES "[Vv][Cc][Pp][Kk][Gg]")
        message(FATAL_ERROR "Repository build surface must not reference vcpkg: ${content_name}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "include\\(FetchContent\\)"
        "project\\(cnode VERSION 1\\.0\\.0 LANGUAGES C CXX\\)"
        "FetchContent_Declare\\([ \t\r\n]*asio"
        "GIT_REPOSITORY https://github\\.com/chriskohlhoff/asio\\.git"
        "FetchContent_Declare\\([ \t\r\n]*aws_lc"
        "GIT_REPOSITORY https://github\\.com/aws/aws-lc\\.git"
        "GIT_TAG v1\\.73\\.0"
        "FetchContent_Declare\\([ \t\r\n]*zlib"
        "GIT_REPOSITORY https://github\\.com/madler/zlib\\.git"
        "add_library\\(cnode_zlib STATIC"
        "FetchContent_Declare\\([ \t\r\n]*concurrentqueue"
        "GIT_REPOSITORY https://github\\.com/cameron314/concurrentqueue\\.git"
        "GIT_TAG v1\\.0\\.5"
        "CNODE_AWSLC_NO_ASM"
        "Using AWS-LC via FetchContent"
        "Using moodycamel ConcurrentQueue via FetchContent")
    if(NOT cmake_source MATCHES "${pattern}")
        message(FATAL_ERROR "CMake must keep FetchContent dependency wiring: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "find_package\\(OpenSSL"
        "OpenSSL::SSL"
        "OpenSSL::Crypto"
        "find_package\\(asio"
        "find_package\\(ZLIB"
        "find_package\\(concurrentqueue")
    if(cmake_source MATCHES "${pattern}")
        message(FATAL_ERROR "CMake must not use package-manager OpenSSL/asio/zlib/concurrentqueue lookups: ${pattern}")
    endif()
endforeach()

foreach(content_name IN ITEMS cmake_source ci_workflow readme)
    if("${${content_name}}" MATCHES "[Mm][Ii][Mm][Aa][Ll][Ll][Oo][Cc]")
        message(FATAL_ERROR "mimalloc dependency must not reappear: ${content_name}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "apk add --no-cache"
        "sudo apt-get install -y"
        "perl nasm"
        "actions/cache/restore@v4"
        "actions/cache/save@v4"
        "if: always\\(\\)"
        "path: build-musl/_deps"
        "path: build-heaptrack/_deps"
        "-DCNODE_HEAPTRACK_BUILD=ON"
        "name: cnode-musl-assets"
        "name: cnode-glibc-assets")
    if(NOT ci_workflow MATCHES "${pattern}")
        message(FATAL_ERROR "CI must install AWS-LC tools and publish both binary variants: ${pattern}")
    endif()
endforeach()

string(CONCAT deprecated_cache_input "save" "-always")
string(CONCAT deprecated_fetchcontent_api "FetchContent" "_Populate")
string(CONCAT removed_sanitizer_option "SANI" "TIZER")
string(CONCAT removed_sanitizer_label "Sani" "tizer")

foreach(pattern IN ITEMS
        "${deprecated_cache_input}"
        "${deprecated_fetchcontent_api}"
        "${removed_sanitizer_option}"
        "${removed_sanitizer_label}")
    if(cmake_source MATCHES "${pattern}" OR ci_workflow MATCHES "${pattern}")
        message(FATAL_ERROR "CMake/CI warning cleanup regressed: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "CMAKE_TOOLCHAIN_FILE"
        "VCPKG_TARGET_TRIPLET")
    if(ci_workflow MATCHES "${pattern}")
        message(FATAL_ERROR "CI must not pass vcpkg toolchain settings: ${pattern}")
    endif()
endforeach()
