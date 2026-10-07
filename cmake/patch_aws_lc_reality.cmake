function(cnode_patch_aws_lc_reality aws_lc_source_dir)
    set(marker "SSL_set_reality_client_hello_cb")
    set(header "${aws_lc_source_dir}/include/openssl/ssl.h")
    set(patch_file "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/aws-lc-reality-sigalg.patch")

    if(NOT EXISTS "${header}")
        message(FATAL_ERROR "AWS-LC ssl.h not found at ${header}")
    endif()

    file(READ "${header}" header_text)
    if(header_text MATCHES "${marker}")
        message(STATUS "AWS-LC REALITY signature algorithm patch already applied")
        return()
    endif()

    find_package(Git REQUIRED)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${patch_file}"
        WORKING_DIRECTORY "${aws_lc_source_dir}"
        RESULT_VARIABLE patch_result
        OUTPUT_VARIABLE patch_stdout
        ERROR_VARIABLE patch_stderr
    )
    if(NOT patch_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to apply AWS-LC REALITY signature algorithm patch\n"
            "${patch_stdout}\n${patch_stderr}")
    endif()
    message(STATUS "Applied AWS-LC REALITY signature algorithm patch")
endfunction()

function(cnode_patch_aws_lc_tls_buffer aws_lc_source_dir)
    set(marker "cnode_set_tls_buffer_allocator")
    set(source "${aws_lc_source_dir}/ssl/ssl_buffer.cc")
    set(patch_file "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/aws-lc-tls-buffer.patch")

    if(NOT EXISTS "${source}")
        message(FATAL_ERROR "AWS-LC ssl_buffer.cc not found at ${source}")
    endif()

    file(READ "${source}" source_text)
    if(source_text MATCHES "${marker}")
        message(STATUS "AWS-LC TLS buffer allocator patch already applied")
        return()
    endif()

    find_package(Git REQUIRED)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${patch_file}"
        WORKING_DIRECTORY "${aws_lc_source_dir}"
        RESULT_VARIABLE patch_result
        OUTPUT_VARIABLE patch_stdout
        ERROR_VARIABLE patch_stderr
    )
    if(NOT patch_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to apply AWS-LC TLS buffer allocator patch\n"
            "${patch_stdout}\n${patch_stderr}")
    endif()
    message(STATUS "Applied AWS-LC TLS buffer allocator patch")
endfunction()

function(cnode_patch_aws_lc_bio_idle aws_lc_source_dir)
    set(marker "cnode_release_empty_bio_pair_buffers")
    set(source "${aws_lc_source_dir}/crypto/bio/pair.c")
    set(patch_file "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/aws-lc-bio-idle.patch")

    if(NOT EXISTS "${source}")
        message(FATAL_ERROR "AWS-LC pair.c not found at ${source}")
    endif()

    file(READ "${source}" source_text)
    if(source_text MATCHES "${marker}")
        message(STATUS "AWS-LC idle BIO buffer patch already applied")
        return()
    endif()

    find_package(Git REQUIRED)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${patch_file}"
        WORKING_DIRECTORY "${aws_lc_source_dir}"
        RESULT_VARIABLE patch_result
        OUTPUT_VARIABLE patch_stdout
        ERROR_VARIABLE patch_stderr
    )
    if(NOT patch_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to apply AWS-LC idle BIO buffer patch\n"
            "${patch_stdout}\n${patch_stderr}")
    endif()
    message(STATUS "Applied AWS-LC idle BIO buffer patch")
endfunction()

if(DEFINED AWS_LC_SOURCE_DIR)
    cnode_patch_aws_lc_reality("${AWS_LC_SOURCE_DIR}")
    cnode_patch_aws_lc_tls_buffer("${AWS_LC_SOURCE_DIR}")
    cnode_patch_aws_lc_bio_idle("${AWS_LC_SOURCE_DIR}")
endif()
