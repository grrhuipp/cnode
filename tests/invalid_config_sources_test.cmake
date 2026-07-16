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
expect_rejected(negative_route_port "{}" "routing.json"
    [=[{"rules":[{"port":"-1","outboundTag":"direct"}]}]=])
expect_rejected(overflow_route_port "{}" "routing.json"
    [=[{"rules":[{"port":"70000","outboundTag":"direct"}]}]=])
expect_rejected(trailing_route_port "{}" "routing.json"
    [=[{"rules":[{"port":"80junk","outboundTag":"direct"}]}]=])
expect_rejected(reversed_route_port_range "{}" "routing.json"
    [=[{"rules":[{"port":"1000-200","outboundTag":"direct"}]}]=])
expect_rejected(floating_route_source_port "{}" "routing.json"
    [=[{"rules":[{"sourcePort":443.0,"outboundTag":"direct"}]}]=])
expect_rejected(unsupported_outbound "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"does-not-exist"}]]=])
expect_rejected(invalid_vmess_outbound "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{}}]]=])
expect_rejected(overflow_vmess_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":65536,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}}]]=])
expect_rejected(negative_vless_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vless","settings":{"server":"example.com","server_port":-1,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]]=])
expect_rejected(string_trojan_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"trojan","settings":{"server":"example.com","server_port":"443","password":"secret"}}]]=])
expect_rejected(overflow_ss_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":65536,"method":"aes-256-gcm","password":"secret"}}]]=])
expect_rejected(invalid_anytls_preferred_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":"bad","port":443,"password":"secret"}}]]=])
expect_rejected(unsupported_inbound "{}" "inbounds.json"
    [=[[{"tag":"bad","protocol":"does-not-exist","port":12001,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(invalid_ss_inbound "{}" "inbounds.json"
    [=[[{"tag":"bad-ss","protocol":"shadowsocks","port":12002,"settings":{"method":"not-a-cipher","password":"secret"}}]]=])
expect_rejected(invalid_vmess_inbound "{}" "inbounds.json"
    [=[[{"tag":"bad-vmess","protocol":"vmess","port":12003,"settings":{"clients":[{"id":"not-a-uuid"}]}}]]=])
expect_rejected(partial_vmess_users "{}" "inbounds.json"
    [=[[{"tag":"partial-vmess","protocol":"vmess","port":12004,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"},{"id":"not-a-uuid"}]}}]]=])
expect_rejected(empty_trojan_users "{}" "inbounds.json"
    [=[[{"tag":"empty-trojan","protocol":"trojan","port":12005,"settings":{"clients":[]}}]]=])
expect_rejected(missing_inbound_port "{}" "inbounds.json"
    [=[[{"tag":"missing-port","protocol":"vmess","settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(negative_inbound_port "{}" "inbounds.json"
    [=[[{"tag":"negative-port","protocol":"vmess","port":-1,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(overflow_inbound_port "{}" "inbounds.json"
    [=[[{"tag":"overflow-port","protocol":"vmess","port":65536,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(uint64_overflow_inbound_port "{}" "inbounds.json"
    [=[[{"tag":"uint64-overflow-port","protocol":"vmess","port":18446744073709551615,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(string_inbound_port "{}" "inbounds.json"
    [=[[{"tag":"string-port","protocol":"vmess","port":"12006","settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(invalid_inbound_listen "{}" "inbounds.json"
    [=[[{"tag":"invalid-listen","protocol":"vmess","listen":"not-an-ip","port":12007,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}]]=])
expect_rejected(duplicate_inbound_tag "{}" "inbounds.json"
    [=[[{"tag":"duplicate","protocol":"vmess","listen":"127.0.0.1","port":12008,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}},{"tag":"duplicate","protocol":"vmess","listen":"127.0.0.2","port":12008,"settings":{"clients":[{"id":"22f6ee21-7dd1-4e62-9cf3-96ca6c7e8b72"}]}}]]=])
expect_rejected(duplicate_inbound_endpoint "{}" "inbounds.json"
    [=[[{"tag":"first","protocol":"vmess","listen":"127.0.0.1","port":12009,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}},{"tag":"second","protocol":"vmess","listen":"127.0.0.1","port":12009,"settings":{"clients":[{"id":"22f6ee21-7dd1-4e62-9cf3-96ca6c7e8b72"}]}}]]=])

file(REMOVE_RECURSE "${TEST_ROOT}")
