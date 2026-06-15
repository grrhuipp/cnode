file(READ "${PROJECT_SOURCE_DIR}/CMakeLists.txt" cmake_source)
file(READ "${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml" ci_workflow)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/allocator.hpp" allocator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap.cpp" bootstrap_source)

string(CONCAT removed_allocator "[Mm][Ii][Mm][Aa][Ll][Ll][Oo][Cc]")

foreach(content_name IN ITEMS cmake_source ci_workflow allocator_header bootstrap_source)
    if("${${content_name}}" MATCHES "${removed_allocator}|USE_MIMALLOC|MI_BUILD_|mi_")
        message(FATAL_ERROR "external allocator dependency must not reappear: ${content_name}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "Allocator: system"
        "cnode_zlib")
    if(NOT cmake_source MATCHES "${pattern}")
        message(FATAL_ERROR "CMake must keep the system allocator build surface: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "Release \\(musl static system allocator\\)"
        "variants: musl\\+system-allocator, glibc\\+system-allocator")
    if(NOT ci_workflow MATCHES "${pattern}")
        message(FATAL_ERROR "CI/release notes must describe system allocator variants: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "std::align_val_t"
        "malloc_trim"
        "M_ARENA_MAX")
    if(NOT allocator_header MATCHES "${pattern}")
        message(FATAL_ERROR "system allocator wrapper must keep RSS/alignment safeguards: ${pattern}")
    endif()
endforeach()
