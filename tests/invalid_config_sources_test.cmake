if(NOT DEFINED CNODE_EXE)
    message(FATAL_ERROR "CNODE_EXE is required")
endif()
if(NOT DEFINED TEST_ROOT)
    message(FATAL_ERROR "TEST_ROOT is required")
endif()

file(TO_CMAKE_PATH "${CMAKE_CURRENT_LIST_FILE}" EXISTING_TEST_FILE)
string(REPEAT "a" 256 ALPN_TOO_LONG)
set(VALID_REALITY_KEY "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

function(normalize_test_sidecar input output)
    set(normalized "${input}")
    string(REPLACE "unused-before-dial" "${VALID_REALITY_KEY}"
        normalized "${normalized}")
    string(REPLACE "unused-before-handshake" "${VALID_REALITY_KEY}"
        normalized "${normalized}")
    string(REPLACE "invalid-until-after-version-validation"
        "${VALID_REALITY_KEY}" normalized "${normalized}")
    set(${output} "${normalized}" PARENT_SCOPE)
endfunction()

function(expect_rejected case_name main_content sidecar_name sidecar_content)
    set(case_dir "${TEST_ROOT}/${case_name}")
    file(REMOVE_RECURSE "${case_dir}")
    file(MAKE_DIRECTORY "${case_dir}")
    file(WRITE "${case_dir}/config.json" "${main_content}")
    if(NOT "${sidecar_name}" STREQUAL "")
        normalize_test_sidecar("${sidecar_content}" normalized_sidecar)
        file(WRITE "${case_dir}/${sidecar_name}" "${normalized_sidecar}")
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
    if(ARGC GREATER 4)
        set(output "${stdout}\n${stderr}")
        if(NOT "${output}" MATCHES "${ARGV4}")
            message(FATAL_ERROR
                "${case_name}: rejection lost expected cause '${ARGV4}'\nstdout=${stdout}\nstderr=${stderr}")
        endif()
    endif()
endfunction()

function(expect_started case_name main_content sidecar_name sidecar_content)
    set(case_dir "${TEST_ROOT}/${case_name}")
    file(REMOVE_RECURSE "${case_dir}")
    file(MAKE_DIRECTORY "${case_dir}")
    file(WRITE "${case_dir}/config.json" "${main_content}")
    if(NOT "${sidecar_name}" STREQUAL "")
        normalize_test_sidecar("${sidecar_content}" normalized_sidecar)
        file(WRITE "${case_dir}/${sidecar_name}" "${normalized_sidecar}")
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
expect_rejected(non_object_timeouts
    [=[{"workers":1,"timeouts":[]}]=] "" ""
    "timeouts must be an object")
expect_rejected(non_object_log
    [=[{"log":false}]=] "" "" "log must be an object")
expect_rejected(non_object_dns
    [=[{"dns":[]}]=] "" "" "dns must be an object")
expect_rejected(non_object_limits
    [=[{"limits":"none"}]=] "" "" "limits must be an object")
expect_rejected(non_array_panels
    [=[{"panels":{}}]=] "" "" "panels must be an array")
expect_rejected(orphan_panel_tls_certificate
    "{\"panels\":[{\"Name\":\"orphan-tls\",\"Type\":\"V2board\",\"APIHost\":\"http://127.0.0.1\",\"Key\":\"secret\",\"NodeIDs\":[1],\"NodeType\":\"vmess\",\"TLSEnable\":true,\"TLSCert\":\"${EXISTING_TEST_FILE}\"}]}"
    "" "")
expect_rejected(overflow_workers
    [=[{"workers":4294967296}]=] "" "")
expect_rejected(excessive_workers
    [=[{"workers":4294967295}]=] "" "")
expect_rejected(string_workers
    [=[{"workers":"4"}]=] "" "")
expect_rejected(negative_log_retention
    [=[{"log":{"maxDays":-1}}]=] "" ""
    "between 0 and 65535")
expect_rejected(non_integer_log_retention
    [=[{"log":{"maxDays":"15"}}]=] "" ""
    "must be an integer between 0 and 65535")
expect_rejected(overflow_log_retention
    [=[{"log":{"maxDays":18446744073709551615}}]=] "" ""
    "between 0 and 65535")
expect_started(valid_zero_log_retention
    [=[{"workers":1,"log":{"maxDays":0}}]=] "" "")
expect_rejected(non_boolean_log_compression
    [=[{"log":{"gzip":"false"}}]=] "" ""
    "gzip must be a boolean")
expect_rejected(conflicting_log_compression
    [=[{"log":{"gzip":true,"compress":false}}]=] "" ""
    "gzip and compress must match")
expect_started(equal_log_compression_aliases
    [=[{"workers":1,"log":{"gzip":false,"compress":false}}]=] "" "")
expect_rejected(non_string_log_level
    [=[{"log":{"loglevel":123}}]=] "" ""
    "loglevel must be a string")
expect_rejected(non_string_transport_network "{}" "outbounds.json"
    [=[[{"tag":"bad-network-type","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":123,"security":"none"}}]]=]
    "network must be a string")
expect_rejected(non_string_http_header "{}" "outbounds.json"
    [=[[{"tag":"bad-header-type","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/ws","headers":{"Host":42,"X-Valid":"yes"}}}}]]=]
    "HTTP header 'Host' must be a string")
expect_rejected(injected_ws_request_path "{}" "outbounds.json"
    [=[[{"tag":"bad-ws-path","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/ws\r\nInjected: yes"}}}]]=]
    "ws path must be a valid HTTP request target")
expect_rejected(injected_http_upgrade_host "{}" "outbounds.json"
    [=[[{"tag":"bad-http-upgrade-host","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"httpupgrade","security":"none","httpupgradeSettings":{"path":"/up","host":"example.com\r\nInjected: yes"}}}]]=]
    "http upgrade host must be a valid HTTP authority")
expect_rejected(invalid_http_method "{}" "outbounds.json"
    [=[[{"tag":"bad-http-method","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"h2","security":"none","httpSettings":{"path":"/h2","method":"GE T"}}}]]=]
    "http method must be a valid HTTP token")
expect_rejected(invalid_grpc_authority "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-authority","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"authority":"bad host","serviceName":"svc"}}}]]=]
    "grpc authority must be a valid HTTP authority")
expect_rejected(injected_grpc_user_agent "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-user-agent","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc","userAgent":"grpc-go/1.0\r\nInjected: yes"}}}]]=]
    "grpc userAgent contains invalid control characters")
expect_rejected(invalid_ws_real_ip_header "{}" "outbounds.json"
    [=[[{"tag":"bad-real-ip-header","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/ws","realIpHeader":"Bad Header"}}}]]=]
    "ws realIpHeader must be a valid HTTP header name")
expect_rejected(invalid_host_header_authority "{}" "outbounds.json"
    [=[[{"tag":"bad-host-authority","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/ws","headers":{"Host":"bad host"}}}}]]=]
    "HTTP header 'host' must be a valid HTTP authority")
expect_started(valid_safe_http_request_components
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-http-components","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/ws?ed=2048","realIpHeader":"X-Real-IP","headers":{"Host":"[2001:db8::1]:443"}}}}]]=])
expect_rejected(non_object_http_headers "{}" "outbounds.json"
    [=[[{"tag":"bad-headers-shape","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"headers":[]}}}]]=]
    "headers must be an object")
expect_rejected(invalid_http_header_name "{}" "outbounds.json"
    [=[[{"tag":"bad-header-name","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"headers":{"Bad Header":"value"}}}}]]=]
    "HTTP header name is invalid")
expect_rejected(injected_http_header_value "{}" "outbounds.json"
    [=[[{"tag":"bad-header-value","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"headers":{"Host":"example.com\r\nInjected: yes"}}}}]]=]
    "HTTP header 'host' contains invalid control characters")
expect_rejected(conflicting_http_header_case_aliases "{}" "outbounds.json"
    [=[[{"tag":"bad-header-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"headers":{"Host":"one.example","host":"two.example"}}}}]]=]
    "HTTP header 'host' has conflicting values")
expect_started(equal_http_header_case_aliases
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-header-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/ws","headers":{"Host":"same.example","host":"same.example"}}}}]]=])
expect_rejected(non_object_outbound_stream_settings "{}" "outbounds.json"
    [=[[{"tag":"bad-stream-settings","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":[]}]]=]
    "streamSettings must be an object")
expect_rejected(non_object_tls_settings "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-settings","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":[]}}]]=]
    "tlsSettings must be an object")
expect_rejected(non_object_tls_certificate "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-certificate","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[42]}}}]]=]
    "tls certificates entries must be objects")
expect_rejected(non_string_tls_min_version "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-min-version-type","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","minVersion":1.3}}}]]=]
    "minVersion must be a string")
expect_rejected(unsupported_tls_min_version "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-min-version","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","minVersion":"1.1"}}}]]=]
    "tls minVersion must be 1.2 or 1.3")
expect_rejected(inverted_tls_versions "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-version-order","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","minVersion":"1.3","maxVersion":"1.2"}}}]]=]
    "tls minVersion must not exceed maxVersion")
expect_rejected(conflicting_tls_min_version_aliases "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-min-version-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","minVersion":"1.2","min_version":"1.3"}}}]]=]
    "minVersion and min_version must match")
expect_rejected(incompatible_reality_tls_version "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-tls-version","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","tlsSettings":{"minVersion":"1.2"},"realitySettings":{"serverName":"example.com","publicKey":"invalid-until-after-version-validation"}}}]]=]
    "reality requires TLS minVersion and maxVersion 1.3")
expect_started(equal_tls_version_aliases
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-tls-version-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","minVersion":"1.3","min_version":"1.3","maxVersion":"1.3","max_version":"1.3"}}}]]=])
expect_rejected(empty_tls_alpn "{}" "outbounds.json"
    [=[[{"tag":"bad-empty-alpn","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":[""]}}}]]=]
    "tls alpn entries must contain between 1 and 255 bytes")
expect_rejected(overlong_tls_alpn "{}" "outbounds.json"
    "[{\"tag\":\"bad-long-alpn\",\"protocol\":\"vless\",\"settings\":{\"server\":\"example.com\",\"server_port\":443,\"uuid\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"encryption\":\"none\"},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"example.com\",\"alpn\":[\"${ALPN_TOO_LONG}\"]}}}]"
    "tls alpn entries must contain between 1 and 255 bytes")
expect_rejected(duplicate_tls_alpn "{}" "outbounds.json"
    [=[[{"tag":"bad-duplicate-alpn","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":["h2","h2"]}}}]]=]
    "tls alpn entries must contain between 1 and 255 bytes and must be unique")
expect_rejected(non_string_tls_ca "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-ca","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","caFile":42}}}]]=]
    "caFile must be a string")
expect_rejected(conflicting_tls_ca_aliases "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-ca-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","caFile":"one.pem","ca_file":"two.pem"}}}]]=]
    "caFile and ca_file must match")
expect_rejected(insecure_tls_ca "{}" "outbounds.json"
    [=[[{"tag":"bad-insecure-ca","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true,"caFile":"ca.pem"}}}]]=]
    "tls caFile cannot be used with allowInsecure")
expect_rejected(inbound_tls_ca "{}" "inbounds.json"
    [=[[{"tag":"bad-inbound-ca","protocol":"vless","listen":"127.0.0.1","port":43191,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"caFile":"ca.pem"}}}]]=]
    "inbound tls caFile is not supported")
expect_rejected(inbound_allow_insecure "{}" "inbounds.json"
    [=[[{"tag":"bad-inbound-insecure","protocol":"vless","listen":"127.0.0.1","port":43192,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true}}}]]=]
    "inbound tls allowInsecure is not supported")
expect_started(equal_tls_ca_aliases
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-tls-ca-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","caFile":"same.pem","ca_file":"same.pem"}}}]]=])
expect_rejected(non_array_tls_certificates "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-certificates","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":{}}}}]]=]
    "tls certificates must be an array")
expect_rejected(multiple_tls_certificates "{}" "outbounds.json"
    [=[[{"tag":"bad-multiple-certificates","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"certificateFile":"one.pem","keyFile":"one.key"},{"certificateFile":"two.pem","keyFile":"two.key"}]}}}]]=]
    "multiple TLS certificates are not supported")
expect_rejected(incomplete_tls_certificate_entry "{}" "outbounds.json"
    [=[[{"tag":"bad-incomplete-certificate","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"certificateFile":"cert.pem"}]}}}]]=]
    "must provide certificateFile and keyFile")
expect_rejected(orphan_tls_cert_file "{}" "outbounds.json"
    [=[[{"tag":"bad-orphan-cert","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certFile":"cert.pem"}}}]]=]
    "tls certFile and keyFile must be configured together")
expect_rejected(conflicting_tls_certificate_sources "{}" "outbounds.json"
    [=[[{"tag":"bad-certificate-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"certificateFile":"array.pem","keyFile":"array.key"}],"certFile":"direct.pem","keyFile":"direct.key"}}}]]=]
    "tls certificates and certFile/keyFile must match")
expect_started(equal_tls_certificate_sources
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-certificate-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"certificateFile":"same.pem","keyFile":"same.key"}],"certFile":"same.pem","keyFile":"same.key"}}}]]=])
expect_rejected(conflicting_outbound_stream_settings_aliases "{}" "outbounds.json"
    [=[[{"tag":"bad-stream-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"none"},"stream_settings":{"network":"grpc","security":"none"}}]]=]
    "streamSettings and stream_settings must match")
expect_rejected(conflicting_grpc_service_names "{}" "outbounds.json"
    [=[[{"tag":"bad-grpc-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"one","service_name":"two"}}}]]=]
    "serviceName and service_name must match")
expect_started(equal_grpc_service_name_aliases
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-grpc-alias","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"grpc","security":"none","grpcSettings":{"serviceName":"same","service_name":"same"}}}]]=])
expect_rejected(non_boolean_tls_allow_insecure "{}" "outbounds.json"
    [=[[{"tag":"bad-tls-bool","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":"true"}}}]]=]
    "allowInsecure must be a boolean")
expect_rejected(invalid_reality_min_client_version "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-version","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"minClientVer":"1.8.0.1"}}}]]=]
    "REALITY minClientVer is invalid")
expect_rejected(reversed_reality_client_version_range "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-range","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"minClientVer":"2.0.0","maxClientVer":"1.9.0"}}}]]=]
    "REALITY minClientVer must not exceed maxClientVer")
expect_rejected(negative_read_timeout
    [=[{"timeouts":{"read":-1}}]=] "" "")
expect_rejected(conflicting_idle_timeout_aliases
    [=[{"timeouts":{"connIdle":30,"idle":60}}]=] "" ""
    "connIdle and idle must match")
expect_started(equal_idle_timeout_aliases
    [=[{"workers":1,"timeouts":{"connIdle":30,"idle":30}}]=] "" "")
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
expect_rejected(non_object_static_user "{}" "inbounds.json"
    [=[[{"tag":"bad-static-user","protocol":"vmess","listen":"127.0.0.1","port":12100,"settings":{"clients":[42,{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"none"}}]]=]
    "clients entries must be objects")
expect_rejected(non_array_static_users "{}" "inbounds.json"
    [=[[{"tag":"bad-static-users","protocol":"vmess","listen":"127.0.0.1","port":12100,"settings":{"clients":{}},"streamSettings":{"network":"tcp","security":"none"}}]]=]
    "clients must be an array")
expect_rejected(non_string_static_user_id "{}" "inbounds.json"
    [=[[{"tag":"bad-static-user-id","protocol":"vmess","listen":"127.0.0.1","port":12100,"settings":{"clients":[{"id":42,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"none"}}]]=]
    "id must be a string")
expect_rejected(non_string_static_cipher_method "{}" "inbounds.json"
    [=[[{"tag":"bad-static-method","protocol":"shadowsocks","listen":"127.0.0.1","port":12100,"settings":{"method":42,"password":"secret"},"streamSettings":{"network":"tcp","security":"none"}}]]=]
    "method must be a string")
expect_rejected(conflicting_static_user_array_aliases "{}" "inbounds.json"
    [=[[{"tag":"bad-static-user-alias","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"users":[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}]},"streamSettings":{"network":"tcp","security":"none"}}]]=]
    "clients and users must match")
expect_started(equal_static_user_array_aliases
    [=[{"workers":1}]=] "inbounds.json"
    [=[[{"tag":"valid-static-user-alias","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"none"}}]]=])
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
expect_rejected(non_string_route_domain_suffix "{}" "routing.json"
    [=[{"rules":[{"domainSuffix":["example.com",42],"outboundTag":"direct"}]}]=]
    "domainSuffix must contain only strings")
expect_rejected(non_array_route_domain_suffix "{}" "routing.json"
    [=[{"rules":[{"domainSuffix":"example.com","outboundTag":"direct"}]}]=]
    "domainSuffix must be an array of strings")
expect_rejected(conflicting_route_domain_suffix_aliases "{}" "routing.json"
    [=[{"rules":[{"domainSuffix":["one.example"],"domain_suffix":["two.example"],"outboundTag":"direct"}]}]=]
    "domainSuffix and domain_suffix must match")
expect_started(equal_route_domain_suffix_aliases
    [=[{"workers":1}]=] "routing.json"
    [=[{"rules":[{"domainSuffix":["same.example"],"domain_suffix":["same.example"],"outboundTag":"direct"}]}]=])
expect_rejected(conflicting_route_inbound_tag_aliases "{}" "routing.json"
    [=[{"rules":[{"inboundTag":"one","inbound_tag":"two","outboundTag":"direct"}]}]=]
    "inboundTag and inbound_tag must match")
expect_rejected(conflicting_route_source_port_aliases "{}" "routing.json"
    [=[{"rules":[{"sourcePort":"80,443","source_port":[80,8443],"outboundTag":"direct"}]}]=]
    "sourcePort and source_port must match")
expect_rejected(conflicting_route_outbound_tag_aliases "{}" "routing.json"
    [=[{"rules":[{"network":"tcp","outboundTag":"direct","outbound_tag":"blocked"}]}]=]
    "outboundTag and outbound_tag must match")
expect_rejected(conflicting_route_domain_strategy_aliases "{}" "routing.json"
    [=[{"domainStrategy":"AsIs","domain_strategy":"IPIfNonMatch","rules":[{"network":"tcp","outboundTag":"direct"}]}]=]
    "domainStrategy and domain_strategy must match")
expect_started(equal_normalized_route_aliases
    [=[{"workers":1}]=] "routing.json"
    [=[{"domainStrategy":"AsIs","domain_strategy":"AsIs","rules":[{"inboundTag":"in-a,in-b","inbound_tag":["in-a","in-b"],"sourcePort":"80,443","source_port":[80,443],"outboundTag":"direct","outbound_tag":"direct"}]}]=])
expect_rejected(empty_route_domain_keyword "{}" "routing.json"
    [=[{"rules":[{"domain":["keyword:"],"outboundTag":"direct"}]}]=]
    "routing domain keyword must not be empty")
expect_rejected(empty_route_domain_regexp "{}" "routing.json"
    [=[{"rules":[{"domain":["regexp:"],"outboundTag":"direct"}]}]=]
    "routing domain regexp must not be empty")
expect_rejected(invalid_route_domain_regexp "{}" "routing.json"
    [=[{"rules":[{"domain":["regexp:["],"outboundTag":"direct"}]}]=]
    "routing domain regexp")
expect_rejected(invalid_route_domain_name "{}" "routing.json"
    [=[{"rules":[{"domain":["domain:bad..example"],"outboundTag":"direct"}]}]=]
    "routing domain suffix contains invalid DNS hostname")
expect_rejected(unsupported_route_network "{}" "routing.json"
    [=[{"rules":[{"network":"quic","outboundTag":"direct"}]}]=]
    "routing network contains unsupported value")
expect_rejected(integer_route_network "{}" "routing.json"
    [=[{"rules":[{"network":1,"outboundTag":"direct"}]}]=]
    "routing network must be a string or array of strings")
expect_rejected(empty_route_network_array "{}" "routing.json"
    [=[{"rules":[{"network":[],"domain":["example.com"],"outboundTag":"direct"}]}]=]
    "routing network must not be empty")
expect_started(canonical_route_network_list
    [=[{"workers":1}]=] "routing.json"
    [=[{"rules":[{"network":"TCP, UDP","outboundTag":"direct"}]}]=])
expect_rejected(empty_route_protocol "{}" "routing.json"
    [=[{"rules":[{"protocol":[""],"outboundTag":"direct"}]}]=]
    "routing protocol must not be empty")
expect_rejected(empty_route_user "{}" "routing.json"
    [=[{"rules":[{"user":[""],"outboundTag":"direct"}]}]=]
    "routing user must not be empty")
expect_rejected(empty_route_geosite "{}" "routing.json"
    [=[{"rules":[{"geosite":[""],"outboundTag":"direct"}]}]=]
    "routing geosite tag must not be empty")
expect_rejected(missing_route_geosite_database "{}" "routing.json"
    [=[{"rules":[{"geosite":["cn"],"outboundTag":"direct"}]}]=]
    "routing geosite tags require")
expect_rejected(missing_route_geoip_database "{}" "routing.json"
    [=[{"rules":[{"geoip":["cn"],"outboundTag":"direct"}]}]=]
    "routing geoip tags require")
expect_rejected(conditionless_route_rule "{}" "routing.json"
    [=[{"rules":[{"outboundTag":"direct"}]}]=]
    "routing rule must contain at least one condition")
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
expect_rejected(invalid_reality_client_short_id "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-short-id","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"not-hex"}}}]]=]
    "REALITY shortId is invalid")
expect_rejected(invalid_reality_server_short_id "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-short-id","protocol":"vless","listen":"127.0.0.1","port":12102,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["not-hex"]}}}]]=]
    "REALITY shortIds contains an invalid value")
expect_rejected(invalid_reality_public_key "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-public-key","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"not-base64url","shortId":"0123456789abcdef"}}}]]=]
    "REALITY publicKey is invalid")
expect_rejected(invalid_reality_private_key "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-private-key","protocol":"vless","listen":"127.0.0.1","port":12103,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"privateKey":"not-base64url","shortIds":["0123456789abcdef"]}}}]]=]
    "REALITY privateKey is invalid")
expect_rejected(missing_reality_outbound_public_key "{}" "outbounds.json"
    [=[[{"tag":"missing-reality-public-key","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","shortId":"0123456789abcdef"}}}]]=]
    "outbound REALITY requires publicKey")
expect_rejected(missing_reality_inbound_private_key "{}" "inbounds.json"
    [=[[{"tag":"missing-reality-private-key","protocol":"vless","listen":"127.0.0.1","port":12104,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"shortIds":["0123456789abcdef"]}}}]]=]
    "inbound REALITY requires privateKey")
expect_rejected(missing_reality_inbound_server_name "{}" "inbounds.json"
    [=[[{"tag":"missing-reality-server-name","protocol":"vless","listen":"127.0.0.1","port":12105,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=]
    "inbound REALITY requires at least one serverName")
expect_rejected(missing_reality_inbound_short_id "{}" "inbounds.json"
    [=[[{"tag":"missing-reality-short-id","protocol":"vless","listen":"127.0.0.1","port":12106,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"privateKey":"unused-before-handshake"}}}]]=]
    "inbound REALITY requires at least one shortId")
expect_started(valid_reality_missing_sni_allowlist
    [=[{"workers":1}]=] "inbounds.json"
    [=[[{"tag":"reality-without-sni","protocol":"vless","listen":"127.0.0.1","port":12107,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":[""],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=])
expect_rejected(unsupported_reality_target_fallback "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-target","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=]
    "target fallback")
expect_rejected(unsupported_reality_target_alias "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-target","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"target":"example.com:443","serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=]
    "dest/target is not supported")
expect_rejected(unsupported_reality_fingerprint "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-fingerprint","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","fingerprint":"chrome"}}}]]=]
    "ClientHello fingerprint")
expect_rejected(unsupported_reality_spider "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-spider","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","spiderX":"/"}}}]]=]
    "REALITY crawler")
expect_rejected(unsupported_reality_spider_alias "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-spider","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","spider_x":"/"}}}]]=]
    "spiderX/spider_x is not supported")
expect_started(valid_native_reality_client
    [=[{"workers":1}]=] "outbounds.json"
    [=[[{"tag":"valid-native-reality","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef"}}}]]=])
expect_rejected(unsupported_reality_mldsa_seed "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-mldsa","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"],"mldsa65Seed":"configured-but-unused"}}}]]=]
    "ML-DSA-65")
expect_rejected(unsupported_reality_mldsa_seed_alias "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-mldsa","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"],"mldsa65_seed":"configured-but-unused"}}}]]=]
    "ML-DSA-65")
expect_rejected(unsupported_reality_mldsa_verify "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-mldsa","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","mldsa65Verify":"configured-but-unused"}}}]]=]
    "signing and verification are not supported")
expect_rejected(unsupported_reality_mldsa_verify_alias "{}" "outbounds.json"
    [=[[{"tag":"bad-reality-mldsa","protocol":"vless","settings":{"server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","publicKey":"unused-before-dial","shortId":"0123456789abcdef","mldsa65_verify":"configured-but-unused"}}}]]=]
    "signing and verification are not supported")
expect_rejected(unsupported_reality_proxy_protocol "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-xver","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"xver":1,"serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=]
    "PROXY protocol forwarding")
expect_rejected(out_of_range_reality_proxy_protocol "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-xver","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"xver":3,"serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=]
    "between 0 and 2")
expect_rejected(non_integer_reality_proxy_protocol "{}" "inbounds.json"
    [=[[{"tag":"bad-reality-xver","protocol":"vless","listen":"127.0.0.1","port":12100,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"xver":"1","serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=]
    "must be an integer between 0 and 2")
expect_started(valid_zero_reality_proxy_protocol
    [=[{"workers":1}]=] "inbounds.json"
    [=[[{"tag":"valid-reality-xver-zero","protocol":"vless","listen":"127.0.0.1","port":12101,"settings":{"decryption":"none","clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"xver":0,"serverNames":["example.com"],"privateKey":"unused-before-handshake","shortIds":["0123456789abcdef"]}}}]]=])
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
