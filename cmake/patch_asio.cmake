function(cnode_patch_asio source_dir)
    find_package(Git REQUIRED)
    # Archive checkouts must not discover the parent project repository.
    get_filename_component(source_parent "${source_dir}" DIRECTORY)
    set(git_apply "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${source_parent}"
        "${GIT_EXECUTABLE}" apply)
    foreach(name IN ITEMS asio-tls-pmr.patch asio-recycling-best-fit.patch)
        set(patch "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/${name}")
        execute_process(COMMAND ${git_apply} --reverse --check "${patch}"
            WORKING_DIRECTORY "${source_dir}" RESULT_VARIABLE applied
            OUTPUT_QUIET ERROR_QUIET)
        if(applied EQUAL 0)
            message(STATUS "Asio patch already applied: ${name}")
            continue()
        endif()
        execute_process(COMMAND ${git_apply} --check "${patch}"
            WORKING_DIRECTORY "${source_dir}" RESULT_VARIABLE checked
            OUTPUT_VARIABLE out ERROR_VARIABLE err)
        if(NOT checked EQUAL 0)
            message(FATAL_ERROR "Asio patch ${name} does not match pinned source: ${out}\n${err}")
        endif()
        execute_process(COMMAND ${git_apply} "${patch}"
            WORKING_DIRECTORY "${source_dir}" RESULT_VARIABLE result
            OUTPUT_VARIABLE out ERROR_VARIABLE err)
        if(NOT result EQUAL 0)
            message(FATAL_ERROR "Failed to apply Asio patch ${name}: ${out}\n${err}")
        endif()
    endforeach()
endfunction()
