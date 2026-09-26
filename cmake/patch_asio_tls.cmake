function(cnode_patch_asio_tls source_dir)
    find_package(Git REQUIRED)
    set(patch "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/asio-tls-pmr.patch")
    # Do not let an archive checkout discover the parent project repository:
    # git apply would otherwise silently skip paths outside that subdirectory.
    get_filename_component(source_parent "${source_dir}" DIRECTORY)
    set(git_apply "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${source_parent}"
        "${GIT_EXECUTABLE}" apply)
    execute_process(COMMAND ${git_apply} --reverse --check "${patch}"
        WORKING_DIRECTORY "${source_dir}" RESULT_VARIABLE applied
        OUTPUT_QUIET ERROR_QUIET)
    if(applied EQUAL 0)
        message(STATUS "Asio TLS PMR/idle buffer patch already applied")
        return()
    endif()
    execute_process(COMMAND ${git_apply} --check "${patch}"
        WORKING_DIRECTORY "${source_dir}" RESULT_VARIABLE checked
        OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT checked EQUAL 0)
        message(FATAL_ERROR "Asio TLS patch does not match the pinned source: ${out}\n${err}")
    endif()
    execute_process(COMMAND ${git_apply} "${patch}"
        WORKING_DIRECTORY "${source_dir}" RESULT_VARIABLE result
        OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Failed to apply Asio TLS patch: ${out}\n${err}")
    endif()
endfunction()
