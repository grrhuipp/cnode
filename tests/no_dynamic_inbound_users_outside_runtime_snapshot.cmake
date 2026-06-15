file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" worker_runtime_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/static_inbound_prepared_config.hpp" static_inbound_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_setup.cpp" bootstrap_setup)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_inbounds.cpp" bootstrap_inbounds)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/manager.cpp" inbound_manager)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/user_store.cpp" user_store)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/vmess/account.hpp" vmess_account_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/trojan/user_info.hpp" trojan_user_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/shadowsocks/user_info.hpp" ss_user_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/anytls/user_info.hpp" anytls_user_header)

if(worker_runtime_config MATCHES "InboundUsersRuntimeEntry" OR
   worker_runtime_config MATCHES "inbound_users" OR
   worker_runtime_config MATCHES "UserSet[ \t\r\n]+users")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must not carry inbound user copies; authentication users live in the global RCU UserStore")
endif()

if(static_inbound_config MATCHES "UserSet[ \t\r\n]+users")
    message(FATAL_ERROR
        "Static inbound runtime entries must not retain protocol user sets after publishing them to UserStore")
endif()

if(worker_header MATCHES "(Apply|Add|Remove|Clear)InboundUsersAsync" OR
   worker_header MATCHES "inbound_users" OR
   worker_source MATCHES "(Apply|Add|Remove|Clear)InboundUsersAsync" OR
   worker_source MATCHES "inbound_users" OR
   bootstrap_setup MATCHES "(Apply|Add|Remove|Clear)InboundUsersAsync" OR
   bootstrap_setup MATCHES "inbound_users" OR
   bootstrap_inbounds MATCHES "(Apply|Add|Remove|Clear)InboundUsersAsync" OR
   bootstrap_inbounds MATCHES "inbound_users")
    message(FATAL_ERROR
        "Worker/bootstrap code must not fan out inbound user updates to per-worker user tables")
endif()

if(controller_source MATCHES "(Apply|Add|Remove|Clear)InboundUsersAsync")
    message(FATAL_ERROR
        "Controller user updates must not be posted to every Worker")
endif()

foreach(pattern IN ITEMS
    "UserStore::AddUsers"
    "UserStore::RemoveUsers"
    "UserStore::ClearUsers")
    if(NOT controller_source MATCHES "${pattern}")
        message(FATAL_ERROR "Controller user updates must publish directly to global UserStore: ${pattern}")
    endif()
endforeach()

foreach(header_name IN ITEMS vmess_account_header trojan_user_header ss_user_header anytls_user_header)
    if("${${header_name}}" MATCHES "\n[ \t]*(std::string|int64_t|uint64_t|uint32_t)[ \t]+(email|user_id|speed_limit|device_limit)[ \t]*;")
        message(FATAL_ERROR
            "Protocol user DTOs must keep common user data in UserProfile instead of redeclaring per-protocol fields: ${header_name}")
    endif()
    if(NOT "${${header_name}}" MATCHES "UserProfile[ \t\r\n]+profile")
        message(FATAL_ERROR
            "Protocol user DTOs must carry the unified UserProfile: ${header_name}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "UserStore::ApplyUsers"
    "UserStore::AddUsers"
    "UserStore::RemoveUsers"
    "UserStore::ClearUsers")
    if(NOT inbound_manager MATCHES "${pattern}")
        message(FATAL_ERROR "Inbound manager compatibility API must delegate to global UserStore: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "std::atomic<std::shared_ptr<const Snapshot>>"
    "compare_exchange_weak"
    "UserStore::Profile"
    "VmessCredential"
    "TrojanCredential"
    "ShadowsocksCredential"
    "AnyTlsCredential")
    if(NOT user_store MATCHES "${pattern}")
        message(FATAL_ERROR "UserStore must be a global RCU store with common profiles and protocol credentials: ${pattern}")
    endif()
endforeach()
