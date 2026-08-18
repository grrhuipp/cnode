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

set(DISPATCHER_BOUNDARY_FILES
    "${SOURCE_DIR}/include/acppnode/features/routing/dispatcher.hpp"
    "${SOURCE_DIR}/include/acppnode/app/dispatcher/default_dispatcher.hpp"
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp")
foreach(DISPATCHER_BOUNDARY_FILE IN LISTS DISPATCHER_BOUNDARY_FILES)
    file(READ "${DISPATCHER_BOUNDARY_FILE}" DISPATCHER_BOUNDARY_SOURCE)
    if(DISPATCHER_BOUNDARY_SOURCE MATCHES
           "ReceiverSettings|proxyman::inbound")
        message(FATAL_ERROR
            "Dispatcher must consume narrow DispatchPolicy, not proxyman receiver state: ${DISPATCHER_BOUNDARY_FILE}")
    endif()
    if(DISPATCHER_BOUNDARY_SOURCE MATCHES
           "acppnode/common/rule|rule::Manager")
        message(FATAL_ERROR
            "Dispatcher must depend on RequestPolicy, not the panel rule manager: ${DISPATCHER_BOUNDARY_FILE}")
    endif()
    if(DISPATCHER_BOUNDARY_SOURCE MATCHES
           "default_outbound|DefaultOutbound|SetDefaultOutbound")
        message(FATAL_ERROR
            "Dispatcher must use the receiver's explicit policy, not mutable global default state: ${DISPATCHER_BOUNDARY_FILE}")
    endif()
endforeach()

file(READ "${SOURCE_DIR}/include/acppnode/features/routing/dispatch_policy.hpp"
     DISPATCH_POLICY_SOURCE)
if(DISPATCH_POLICY_SOURCE MATCHES
       "OutboundSelectionKind|HasOutboundTag")
    message(FATAL_ERROR
        "outbound selection policy must be an exhaustive non-defaultable type")
endif()

file(READ "${SOURCE_DIR}/include/acppnode/app/proxyman/inbound/receiver_settings.hpp"
     RECEIVER_SETTINGS_SOURCE)
if(RECEIVER_SETTINGS_SOURCE MATCHES
       "OutboundSelectionPolicy +outbound_policy *=")
    message(FATAL_ERROR
        "receiver construction must require an explicit outbound selection policy")
endif()

file(READ "${SOURCE_DIR}/src/app/worker/udp_ingress.cpp"
     UDP_INGRESS_SOURCE)
if(UDP_INGRESS_SOURCE MATCHES
       "make_shared<proxyman::inbound::ReceiverSettings> *[(] *[)]")
    message(FATAL_ERROR
        "native UDP must retain its prepared receiver instead of inventing a default policy")
endif()

file(READ "${SOURCE_DIR}/src/app/bootstrap_inbounds.cpp"
     STATIC_INBOUND_BOOTSTRAP_SOURCE)
foreach(STATIC_INBOUND_POLICY_TOKEN IN ITEMS
        "routing_enabled"
        "RouteWithFallback"
        "ForceOutbound")
    if(NOT STATIC_INBOUND_BOOTSTRAP_SOURCE MATCHES
           "${STATIC_INBOUND_POLICY_TOKEN}")
        message(FATAL_ERROR
            "static inbound bootstrap must map routingEnabled=false to ForceOutbound and true to RouteWithFallback")
    endif()
endforeach()

foreach(GLOBAL_DEFAULT_FILE IN ITEMS
        "${SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp"
        "${SOURCE_DIR}/src/app/worker.cpp"
        "${SOURCE_DIR}/src/app/bootstrap_setup.cpp")
    file(READ "${GLOBAL_DEFAULT_FILE}" GLOBAL_DEFAULT_SOURCE)
    if(GLOBAL_DEFAULT_SOURCE MATCHES
           "default_outbound_tag|DefaultOutbound|SetDefaultOutbound")
        message(FATAL_ERROR
            "Worker runtime must not derive or publish an implicit global default outbound: ${GLOBAL_DEFAULT_FILE}")
    endif()
endforeach()

file(READ "${SOURCE_DIR}/include/acppnode/features/routing/dispatcher.hpp"
     DISPATCHER_INTERFACE_SOURCE)
if(DISPATCHER_INTERFACE_SOURCE MATCHES
       "Route[ \t\r\n]*[(]|DispatchResult")
    message(FATAL_ERROR
        "Dispatcher public interface must expose only the canonical Dispatch entry")
endif()

foreach(ROUTER_BOUNDARY_FILE IN ITEMS
        "${SOURCE_DIR}/include/acppnode/app/router/router.hpp"
        "${SOURCE_DIR}/src/app/router/router.cpp")
    file(READ "${ROUTER_BOUNDARY_FILE}" ROUTER_BOUNDARY_SOURCE)
    if(ROUTER_BOUNDARY_SOURCE MATCHES
           "default_outbound|DefaultOutbound|SetDefaultOutbound")
        message(FATAL_ERROR
            "Router must return only matched rules; Dispatcher owns the receiver's explicit fallback: ${ROUTER_BOUNDARY_FILE}")
    endif()
endforeach()

file(READ "${SOURCE_DIR}/include/acppnode/app/router/router.hpp"
     ROUTER_INTERFACE_SOURCE)
if(ROUTER_INTERFACE_SOURCE MATCHES
       "std::string_view +Route *[(]|RouteDetailed|Router *[(] *Router&&")
    message(FATAL_ERROR
        "Router public interface must expose only the complete RouteDecision entry")
endif()

file(READ "${SOURCE_DIR}/include/acppnode/app/dispatcher/default_dispatcher.hpp"
     DEFAULT_DISPATCHER_INTERFACE_SOURCE)
if(DEFAULT_DISPATCHER_INTERFACE_SOURCE MATCHES
       "DefaultDispatcher *[(] *app::router::Router")
    message(FATAL_ERROR
        "Dispatcher must be bound explicitly during Worker runtime initialization")
endif()

foreach(CHILD_DISPATCH_FILE IN ITEMS
        "${SOURCE_DIR}/src/proxy/mux/inbound/mux_inbound.hpp"
        "${SOURCE_DIR}/src/proxy/mux/inbound/mux_inbound.cpp")
    file(READ "${CHILD_DISPATCH_FILE}" CHILD_DISPATCH_SOURCE)
    if(CHILD_DISPATCH_SOURCE MATCHES "ReceiverSettings|proxyman::inbound")
        message(FATAL_ERROR
            "Mux child dispatch must retain only DispatchPolicy: ${CHILD_DISPATCH_FILE}")
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
