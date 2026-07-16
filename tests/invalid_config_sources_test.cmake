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

function(expect_started case_name main_content sidecar_name sidecar_content)
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
        TIMEOUT 1)

    if("${result}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR
            "${case_name}: valid config exited before startup: ${result}\nstdout=${stdout}\nstderr=${stderr}")
    endif()
    if(NOT "${stdout}" MATCHES "server started")
        message(FATAL_ERROR
            "${case_name}: valid config did not reach startup: ${result}\nstdout=${stdout}\nstderr=${stderr}")
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
expect_rejected(overflow_workers
    [=[{"workers":4294967296}]=] "" "")
expect_rejected(excessive_workers
    [=[{"workers":4294967295}]=] "" "")
expect_rejected(string_workers
    [=[{"workers":"4"}]=] "" "")
expect_rejected(negative_read_timeout
    [=[{"timeouts":{"read":-1}}]=] "" "")
expect_rejected(negative_connection_limit
    [=[{"limits":{"maxConnections":-1}}]=] "" "")
expect_rejected(negative_dns_cache_size
    [=[{"dns":{"cacheSize":-1}}]=] "" "")
expect_rejected(invalid_dns_server
    [=[{"dns":{"servers":["not-an-ip"]}}]=] "" "")
expect_rejected(mixed_invalid_dns_server
    [=[{"dns":{"servers":["127.0.0.1","not-an-ip"]}}]=] "" "")
expect_rejected(non_string_dns_server
    [=[{"dns":{"servers":[123]}}]=] "" "")
expect_rejected(scalar_dns_servers
    [=[{"dns":{"servers":"8.8.8.8"}}]=] "" "")
expect_rejected(empty_dns_servers
    [=[{"dns":{"servers":[]}}]=] "" "")
expect_rejected(overflow_panel_api_port
    [=[{"panels":[{"Name":"bad-port","Type":"V2board","APIHost":"http://127.0.0.1:70000","Key":"secret","NodeIDs":[1],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(trailing_panel_api_port
    [=[{"panels":[{"Name":"bad-port","Type":"V2board","APIHost":"http://127.0.0.1:80junk","Key":"secret","NodeIDs":[1],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(empty_panel_api_port
    [=[{"panels":[{"Name":"bad-port","Type":"V2board","APIHost":"http://127.0.0.1:","Key":"secret","NodeIDs":[1],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(invalid_panel_send_ip
    [=[{"panels":[{"Name":"bad-bind","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[1],"NodeType":"vmess","SendIP":"not-an-ip"}]}]=]
    "" "")
expect_rejected(invalid_panel_listen_ip
    [=[{"panels":[{"Name":"bad-listen","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[1],"NodeType":"vmess","ListenIP":"not-an-ip"}]}]=]
    "" "")
expect_rejected(overflow_panel_node_id
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[4294967297],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(signed_overflow_panel_node_id
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[2147483648],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(negative_panel_node_id
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[-1],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(zero_panel_node_id
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[0],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(scalar_panel_node_ids
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":1,"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(mixed_type_panel_node_ids
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[1,"2"],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(duplicate_panel_node_ids
    [=[{"panels":[{"Name":"bad-node","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[1,1],"NodeType":"vmess"}]}]=]
    "" "")
expect_rejected(duplicate_panel_entries
    [=[{"panels":[{"Name":"same","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[1],"NodeType":"vmess"},{"Name":"same","Type":"V2board","APIHost":"http://127.0.0.1","Key":"secret","NodeIDs":[1],"NodeType":"vmess"}]}]=]
    "" "")
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
expect_rejected(trailing_route_ipv4_prefix "{}" "routing.json"
    [=[{"rules":[{"ip":["192.0.2.0/24junk"],"outboundTag":"direct"}]}]=])
expect_rejected(trailing_route_ipv6_prefix "{}" "routing.json"
    [=[{"rules":[{"ip":["2001:db8::/32junk"],"outboundTag":"direct"}]}]=])
expect_rejected(invalid_route_source_cidr "{}" "routing.json"
    [=[{"rules":[{"source":["not-an-ip"],"outboundTag":"direct"}]}]=])
expect_rejected(unsupported_outbound "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"does-not-exist"}]]=])
expect_rejected(invalid_outbound_send_through "{}" "outbounds.json"
    [=[[{"tag":"bad-bind","protocol":"freedom","sendThrough":"not-an-ip"}]]=])
expect_rejected(non_string_outbound_send_through "{}" "outbounds.json"
    [=[[{"tag":"bad-bind","protocol":"freedom","sendThrough":123}]]=])
expect_rejected(invalid_xhttp_download_send_through "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-bind","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","port":443,"sendThrough":"not-an-ip","network":"xhttp","security":"none","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(non_integer_xhttp_download_port "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-port","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","port":"443","network":"xhttp","security":"none","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(missing_xhttp_download_port "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-port","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","network":"xhttp","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(conflicting_xhttp_download_ports "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-port","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","port":443,"server_port":8443,"network":"xhttp","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(missing_xhttp_download_address "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-address","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"port":443,"network":"xhttp","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(conflicting_xhttp_download_addresses "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-address","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","server":"other.example.com","port":443,"network":"xhttp","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(non_xhttp_download_network "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-network","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","port":443,"network":"tcp"}}}}}]]=])
expect_rejected(stream_one_xhttp_download "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-mode","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"downloadSettings":{"address":"download.example.com","port":443,"network":"xhttp","xhttpSettings":{"mode":"stream-one"}}}}}}]]=])
expect_rejected(stream_one_xhttp_upload_with_download "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-mode","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"mode":"stream-one","extra":{"downloadSettings":{"address":"download.example.com","port":443,"network":"xhttp","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(non_object_xhttp_download_settings "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-shape","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"downloadSettings":443}}}]]=])
expect_rejected(duplicate_xhttp_download_settings "{}" "outbounds.json"
    [=[[{"tag":"bad-xhttp-duplicate","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"downloadSettings":{"address":"one.example.com","port":443,"network":"xhttp","xhttpSettings":{"mode":"auto"}},"extra":{"downloadSettings":{"address":"two.example.com","port":443,"network":"xhttp","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(nested_xhttp_download_settings "{}" "outbounds.json"
    [=[[
      {
        "tag":"bad-xhttp-nested",
        "protocol":"vless",
        "settings":{
          "server":"upload.example.com",
          "server_port":443,
          "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811",
          "encryption":"none"
        },
        "streamSettings":{
          "network":"xhttp",
          "security":"none",
          "xhttpSettings":{
            "extra":{
              "downloadSettings":{
                "address":"download.example.com",
                "port":443,
                "network":"xhttp",
                "xhttpSettings":{
                  "mode":"auto",
                  "downloadSettings":{
                    "address":"nested.example.com",
                    "port":443,
                    "network":"xhttp",
                    "xhttpSettings":{"mode":"auto"}
                  }
                }
              }
            }
          }
        }
      }
    ]]=])
expect_started(valid_xhttp_split_download
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-xhttp-split","protocol":"vless","settings":{"server":"upload.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"mode":"auto","extra":{"downloadSettings":{"address":"download.example.com","port":443,"network":"xhttp","security":"none","xhttpSettings":{"mode":"auto"}}}}}}]]=])
expect_rejected(non_integer_grpc_initial_window "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","initialWindowSize":"65535"}}}]]=])
expect_rejected(negative_grpc_initial_window "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","initialWindowSize":-1}}}]]=])
expect_rejected(overflow_grpc_initial_window "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","initialWindowSize":2147483648}}}]]=])
expect_rejected(conflicting_grpc_initial_windows "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","initialWindowSize":65535,"initial_window_size":65536}}}]]=])
expect_rejected(legacy_plural_grpc_initial_window "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","initial_windows_size":65535}}}]]=])
expect_rejected(non_integer_http2_initial_window "{}" "outbounds.json"
    [=[[{"tag":"bad-h2-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"h2","security":"none","httpSettings":{"path":"/h2","initialWindowSize":"65535"}}}]]=])
expect_started(valid_zero_grpc_initial_window
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-grpc-zero-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","initial_window_size":0}}}]]=])
expect_rejected(non_integer_reality_max_time_diff "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-time-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","maxTimeDiff":"60000"}}}]]=])
expect_rejected(negative_reality_max_time_diff "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-time-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","maxTimeDiff":-1}}}]]=])
expect_rejected(conflicting_reality_max_time_diff "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-time-window","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","maxTimeDiff":60000,"max_time_diff":30000}}}]]=])
expect_rejected(invalid_vmess_outbound "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{}}]]=])
expect_rejected(overflow_vmess_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":65536,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}}]]=])
expect_rejected(unsupported_vmess_alter_id "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":64}}]]=])
expect_rejected(unsupported_vmess_alter_id_alias "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alter_id":1}}]]=])
expect_rejected(negative_vmess_alter_id "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":-1}}]]=])
expect_rejected(non_integer_vmess_alter_id "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":"0"}}]]=])
expect_rejected(conflicting_vmess_alter_id_aliases "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0,"alter_id":64}}]]=])
expect_rejected(nested_unsupported_vmess_alter_id "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vmess","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":64}]}]}}]]=])
expect_rejected(negative_vless_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"vless","settings":{"server":"example.com","server_port":-1,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}}]]=])
expect_rejected(string_trojan_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"trojan","settings":{"server":"example.com","server_port":"443","password":"secret"}}]]=])
expect_rejected(overflow_ss_outbound_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":65536,"method":"aes-256-gcm","password":"secret"}}]]=])
expect_rejected(invalid_ss_uot_boolean_version "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","uot":true,"uotVersion":3}}]]=])
expect_rejected(non_boolean_ss_uot "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","uot":"true"}}]]=])
expect_rejected(invalid_ss_uot_object_version "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","udp_over_tcp":{"enabled":true,"version":3}}}]]=])
expect_rejected(non_boolean_ss_uot_enabled "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","udp_over_tcp":{"enabled":1,"version":2}}}]]=])
expect_rejected(conflicting_ss_uot_aliases "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","uot":false,"udp_over_tcp":true}}]]=])
expect_rejected(conflicting_ss_uot_version_aliases "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","uot":true,"uotVersion":1,"uot_version":2}}]]=])
expect_rejected(orphan_ss_uot_version "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","uotVersion":2}}]]=])
expect_rejected(nested_invalid_ss_uot_version "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":"example.com","port":443,"method":"aes-256-gcm","password":"secret","uot":true,"uotVersion":3}]}}]]=])
expect_rejected(invalid_anytls_preferred_port "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":"bad","port":443,"password":"secret"}}]]=])
expect_rejected(non_integer_anytls_idle_check_interval "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":443,"password":"secret","idleSessionCheckInterval":"30"}}]]=])
expect_rejected(zero_anytls_idle_timeout "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":443,"password":"secret","idleSessionTimeout":0}}]]=])
expect_rejected(overflow_anytls_idle_timeout "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":443,"password":"secret","idleSessionTimeout":18446744073709551615}}]]=])
expect_rejected(negative_anytls_min_idle_sessions "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":443,"password":"secret","minIdleSession":-1}}]]=])
expect_rejected(non_integer_anytls_min_idle_sessions "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":443,"password":"secret","minIdleSession":"1"}}]]=])
expect_rejected(conflicting_anytls_idle_timeout_aliases "{}" "outbounds.json"
    [=[[{"tag":"proxy","protocol":"anytls","settings":{"server":"example.com","server_port":443,"password":"secret","idleSessionTimeout":60,"idle_session_timeout":61}}]]=])
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
