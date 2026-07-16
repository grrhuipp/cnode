if(NOT DEFINED CNODE_EXE)
    message(FATAL_ERROR "CNODE_EXE is required")
endif()
if(NOT DEFINED TEST_ROOT)
    message(FATAL_ERROR "TEST_ROOT is required")
endif()

function(expect_rejected case_name main_content sidecar_name sidecar_content)
    set(case_dir "${TEST_ROOT}/${case_name}")
    file(REMOVE_RECURSE "${case_dir}")
    file(MAKE_DIRECTORY "${case_dir}")
    file(WRITE "${case_dir}/config.json" "${main_content}")
    if(NOT "${sidecar_name}" STREQUAL "")
        file(WRITE "${case_dir}/${sidecar_name}" "${sidecar_content}")
    endif()

    execute_process(
        COMMAND "${CNODE_EXE}" --config-dir "${case_dir}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE stdout
        ERROR_VARIABLE stderr
        TIMEOUT 5)

    if("${result}" STREQUAL "0")
        message(FATAL_ERROR
            "${case_name}: invalid config was accepted\nstdout=${stdout}\nstderr=${stderr}")
    endif()
    if(NOT "${result}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR
            "${case_name}: cnode did not reject promptly: ${result}\nstdout=${stdout}\nstderr=${stderr}")
    endif()
endfunction()

expect_rejected(malformed_main "{" "" "")
expect_rejected(malformed_inbounds "{}" "inbounds.json" "{")
expect_rejected(malformed_outbounds "{}" "outbounds.json" "{")
expect_rejected(malformed_routing "{}" "routing.json" "{")
expect_rejected(wrong_shape_inbounds "{}" "inbounds.json" [=[{"inbounds":{}}]=])
expect_rejected(wrong_shape_outbounds "{}" "outbounds.json" [=[{"outbounds":{}}]=])
expect_rejected(wrong_shape_routing "{}" "routing.json" [=[{"routing":[]}]=])
expect_rejected(scalar_inbounds "{}" "inbounds.json" "42")
expect_rejected(scalar_outbounds "{}" "outbounds.json" "42")
expect_rejected(scalar_routing "{}" "routing.json" "42")
expect_rejected(unsupported_outbound "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"does-not-exist"}]]=])
expect_rejected(invalid_vmess_outbound "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{}}]]=])

file(REMOVE_RECURSE "${TEST_ROOT}")
