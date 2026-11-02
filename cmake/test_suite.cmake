# One build/test graph for local runs and every CI libc variant. Test commands
# remain registered beside their targets; CI does not maintain a second list.
if(CNODE_TEST_SANITIZERS)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "CNODE_TEST_SANITIZERS requires Linux GCC or Clang with ASan/UBSan")
    endif()
    foreach(base IN ITEMS cnode_thread_pool_test cnode_timeout_scheduler_test)
        set(target "${base}_sanitized")
        get_target_property(sources ${base} SOURCES)
        add_executable(${target} ${sources})
        # Keep sanitizer instrumentation and fault-injection allocation pairs
        # in their original translation units, independently of release LTO.
        set_target_properties(${target} PROPERTIES
            INTERPROCEDURAL_OPTIMIZATION OFF
            INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF)
        foreach(property IN ITEMS INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_LIBRARIES)
            get_target_property(value ${base} ${property})
            if(value)
                set_property(TARGET ${target} PROPERTY ${property} "${value}")
            endif()
        endforeach()
        target_compile_options(${target} PRIVATE
            -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Werror)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        add_test(NAME ${target} COMMAND ${target})
        set_tests_properties(${target} PROPERTIES TIMEOUT 60
            ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1;UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
    endforeach()
endif()

add_custom_target(cnode_tests)
get_property(targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(target IN LISTS targets)
    get_target_property(type ${target} TYPE)
    if(type STREQUAL "EXECUTABLE" AND target MATCHES "^cnode($|_)")
        add_dependencies(cnode_tests ${target})
    endif()
endforeach()
