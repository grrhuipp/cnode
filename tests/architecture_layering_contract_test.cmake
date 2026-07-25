if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

set(CONCRETE_PROXY_PATTERN
    "vmess|vless|trojan|shadowsocks|anytls|freedom|blackhole")

foreach(LEGACY_LAYER_FILE IN ITEMS
        "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/tcp_worker.hpp"
        "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_worker.hpp"
        "${SOURCE_DIR}/src/app/proxyman/inbound/tcp_worker.cpp"
        "${SOURCE_DIR}/src/app/proxyman/inbound/udp_worker.cpp"
        "${SOURCE_DIR}/src/app/proxyman/outbound/source_config.hpp"
        "${SOURCE_DIR}/src/app/proxyman/outbound/source_config.cpp"
        "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_handler.hpp")
    if(EXISTS "${LEGACY_LAYER_FILE}")
        message(FATAL_ERROR
            "legacy cross-layer surface must not return: ${LEGACY_LAYER_FILE}")
    endif()
endforeach()

foreach(WORKER_PRIVATE_FILE IN ITEMS
        "${SOURCE_DIR}/src/app/worker/tcp_listener.hpp"
        "${SOURCE_DIR}/src/app/worker/tcp_listener.cpp"
        "${SOURCE_DIR}/src/app/worker/udp_ingress.hpp"
        "${SOURCE_DIR}/src/app/worker/udp_ingress.cpp")
    if(NOT EXISTS "${WORKER_PRIVATE_FILE}")
        message(FATAL_ERROR
            "listener/socket/session ownership must remain Worker-private: ${WORKER_PRIVATE_FILE}")
    endif()
endforeach()

file(GLOB_RECURSE PROXYMAN_SOURCES
    "${SOURCE_DIR}/src/app/proxyman/*.cpp"
    "${SOURCE_DIR}/src/app/proxyman/*.hpp")
foreach(PROXYMAN_SOURCE_PATH IN LISTS PROXYMAN_SOURCES)
    file(READ "${PROXYMAN_SOURCE_PATH}" PROXYMAN_SOURCE)
    if(PROXYMAN_SOURCE MATCHES
           "acppnode/infra/json|json::|FromJson[(]|PanelConfig|api::")
        message(FATAL_ERROR
            "proxyman must consume prepared runtime objects, not parse source or panel config: ${PROXYMAN_SOURCE_PATH}")
    endif()
endforeach()

set(CORE_LAYER_FILES
    "${SOURCE_DIR}/src/app/worker.cpp"
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp"
    "${SOURCE_DIR}/src/app/router/router.cpp"
    "${SOURCE_DIR}/src/app/relay_udp.cpp"
    "${SOURCE_DIR}/include/acppnode/app/relay.hpp"
    "${SOURCE_DIR}/src/app/proxyman/inbound/handler.cpp"
    "${SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp"
    "${SOURCE_DIR}/src/app/proxyman/outbound/manager.cpp"
    "${SOURCE_DIR}/src/transport/internet/transport_stack.cpp"
    "${SOURCE_DIR}/src/transport/internet/transport_dialer.cpp")
foreach(CORE_LAYER_FILE IN LISTS CORE_LAYER_FILES)
    file(READ "${CORE_LAYER_FILE}" CORE_LAYER_SOURCE)
    if(CORE_LAYER_SOURCE MATCHES
           "proxy/(${CONCRETE_PROXY_PATTERN})|(${CONCRETE_PROXY_PATTERN})::")
        message(FATAL_ERROR
            "generic runtime layers must not depend on concrete proxy protocols: ${CORE_LAYER_FILE}")
    endif()
endforeach()

set(HOT_PATH_FILES
    "${SOURCE_DIR}/src/app/worker.cpp"
    "${SOURCE_DIR}/src/app/worker/udp_ingress.cpp"
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp"
    "${SOURCE_DIR}/src/app/router/router.cpp"
    "${SOURCE_DIR}/src/app/relay_udp.cpp"
    "${SOURCE_DIR}/include/acppnode/app/relay.hpp"
    "${SOURCE_DIR}/src/app/proxyman/inbound/handler.cpp")
foreach(HOT_PATH_FILE IN LISTS HOT_PATH_FILES)
    file(READ "${HOT_PATH_FILE}" HOT_PATH_SOURCE)
    if(HOT_PATH_SOURCE MATCHES
           "acppnode/infra/json|acppnode/api/|service/controller|json::|PanelConfig|api::")
        message(FATAL_ERROR
            "hot path must not parse JSON or understand panel/control-plane fields: ${HOT_PATH_FILE}")
    endif()
endforeach()

file(GLOB_RECURSE CPP_SOURCES "${SOURCE_DIR}/src/*.cpp")
foreach(CPP_SOURCE_PATH IN LISTS CPP_SOURCES)
    file(TO_CMAKE_PATH "${CPP_SOURCE_PATH}" CPP_SOURCE_NORMALIZED)
    file(READ "${CPP_SOURCE_PATH}" CPP_SOURCE)

    if(CPP_SOURCE MATCHES "outbound_handler->[ \t\r\n]*Process[(]" AND
       NOT CPP_SOURCE_NORMALIZED STREQUAL
           "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp")
        message(FATAL_ERROR
            "only Dispatcher may invoke outbound Handler::Process: ${CPP_SOURCE_PATH}")
    endif()

    if(CPP_SOURCE MATCHES
           "co_await[ \t\r\n]+dispatcher(_)?([.]|->)Dispatch[(]" AND
       NOT CPP_SOURCE_NORMALIZED MATCHES "/src/proxy/[^/]+/inbound/" AND
       NOT CPP_SOURCE_NORMALIZED STREQUAL
           "${SOURCE_DIR}/src/app/worker/udp_ingress.cpp")
        message(FATAL_ERROR
            "only inbound implementations and the native datagram ingress may enter Dispatcher: ${CPP_SOURCE_PATH}")
    endif()

    if(CPP_SOURCE MATCHES
           "co_await[ \t\r\n]+(impl_->proxy|proxy_)->Process[(]" AND
       NOT CPP_SOURCE_NORMALIZED STREQUAL
           "${SOURCE_DIR}/src/app/proxyman/inbound/handler.cpp" AND
       NOT CPP_SOURCE_NORMALIZED STREQUAL
           "${SOURCE_DIR}/src/app/worker/udp_ingress.cpp")
        message(FATAL_ERROR
            "only physical TCP/UDP ingress may invoke inbound Handler::Process: ${CPP_SOURCE_PATH}")
    endif()

    if(CPP_SOURCE MATCHES
           "co_await[ \t\r\n]+Do(RelayLink|RelayLinkWithFirstPacket|UDPRelayLink)[(]" AND
       NOT CPP_SOURCE_NORMALIZED MATCHES
           "/src/proxy/.*outbound[.]cpp$")
        message(FATAL_ERROR
            "only outbound handlers may hand traffic to relay: ${CPP_SOURCE_PATH}")
    endif()
endforeach()

file(GLOB_RECURSE CONTROLLER_SOURCES
    "${SOURCE_DIR}/src/service/controller/*.cpp"
    "${SOURCE_DIR}/src/service/controller/*.hpp")
foreach(CONTROLLER_SOURCE_PATH IN LISTS CONTROLLER_SOURCES)
    file(READ "${CONTROLLER_SOURCE_PATH}" CONTROLLER_SOURCE)
    if(CONTROLLER_SOURCE MATCHES
           "PasswordHash|HashPassword|MemoryAccount|derived_key|identity_key|cmd_key|auth_key")
        message(FATAL_ERROR
            "controller must normalize RuntimeUser, not construct protocol credentials: ${CONTROLLER_SOURCE_PATH}")
    endif()
endforeach()

foreach(PROTOCOL_VALIDATOR IN ITEMS
        "${SOURCE_DIR}/src/proxy/vmess/validator.hpp"
        "${SOURCE_DIR}/src/proxy/vless/validator.hpp"
        "${SOURCE_DIR}/src/proxy/trojan/validator.hpp"
        "${SOURCE_DIR}/src/proxy/shadowsocks/validator.hpp"
        "${SOURCE_DIR}/src/proxy/anytls/validator.hpp")
    file(READ "${PROTOCOL_VALIDATOR}" PROTOCOL_VALIDATOR_SOURCE)
    if(PROTOCOL_VALIDATOR_SOURCE MATCHES
           "ApplyUsers[(]|AddUsers[(]|RemoveUsers[(]|ClearUsers[(]")
        message(FATAL_ERROR
            "validators must be read-only UserStore consumers: ${PROTOCOL_VALIDATOR}")
    endif()
endforeach()
