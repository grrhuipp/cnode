file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/dispatcher/default_dispatcher.hpp" dispatcher_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp" dispatcher_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/router/router.hpp" router_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/router/router.cpp" router_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/relay.hpp" relay_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/relay_types.hpp" relay_types_header)

foreach(pattern IN ITEMS
    "acppnode/proxy/"
    "app/dispatcher/"
    "app/router/"
    "app/relay\\.hpp"
    "app/proxyman/inbound/manager"
    "app/proxyman/outbound/manager"
    "rule/manager")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR "worker.hpp must not expose protocol, dispatcher, router, relay, manager, or rule-manager implementation coupling: ${pattern}")
    endif()
endforeach()

foreach(content IN ITEMS "${dispatcher_header}" "${dispatcher_source}")
    foreach(pattern IN ITEMS
        "acppnode/proxy/vmess"
        "acppnode/proxy/trojan"
        "acppnode/proxy/shadowsocks"
        "proxy/vmess"
        "proxy/trojan"
        "proxy/shadowsocks"
        "app/relay\\.hpp")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Dispatcher must not depend on concrete protocol or relay implementation APIs: ${pattern}")
        endif()
    endforeach()
endforeach()

foreach(content IN ITEMS "${router_header}" "${router_source}")
    foreach(pattern IN ITEMS
        "app/relay"
        "app/proxyman/"
        "acppnode/proxy/"
        "OutboundManager"
        "InboundManager")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Router must not depend on relay, proxyman managers, or concrete protocols: ${pattern}")
        endif()
    endforeach()
endforeach()

foreach(content IN ITEMS "${relay_header}" "${relay_types_header}")
    foreach(pattern IN ITEMS
        "Wrapper"
        "wrapper"
        "VMess"
        "Trojan"
        "Shadowsocks"
        "vless"
        "vmess"
        "trojan"
        "shadowsocks")
        if(content MATCHES "${pattern}")
            message(FATAL_ERROR "Relay public API must remain protocol-neutral and wrapper-free: ${pattern}")
        endif()
    endforeach()
endforeach()
