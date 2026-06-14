file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/udp_session.hpp" udp_session_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_worker.hpp" udp_worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/udp_worker.cpp" udp_worker_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/udp_session.cpp" udp_session_cpp)

if(worker_header MATCHES "app/udp_session\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the full UDP session manager implementation boundary")
endif()

if(udp_worker_header MATCHES "app/udp_session\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound udp_worker.hpp must not include the full UDP session implementation just to store UDPSession pointers")
endif()

if(NOT udp_worker_header MATCHES "app/udp_endpoint_key\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound udp_worker.hpp should depend on the lightweight UDP endpoint key DTO boundary")
endif()

if(worker_header MATCHES "UDPSessionManager[ \t\r\n]+udp_session_manager_")
    message(FATAL_ERROR
        "Worker public header must not store UDPSessionManager by value")
endif()

if(udp_session_header MATCHES "UDPSessionManager[^{]*\\{[^}]*ThreadLocal(UnorderedMap|Vector)" OR
   udp_session_header MATCHES "(sessions_|retired_sessions_|cleanup_timer_|SessionDeleter|SessionPtr)")
    message(FATAL_ERROR
        "UDPSessionManager public header must not expose session maps, retired lists, cleanup timer, or Worker-local manager storage")
endif()

foreach(forbidden_header
        "common\\.hpp"
        "common/allocator\\.hpp"
        "common/session\\.hpp"
        "app/stats\\.hpp"
        "app/udp_endpoint_key\\.hpp")
    if(udp_session_header MATCHES "${forbidden_header}")
        message(FATAL_ERROR
            "udp_session.hpp must not pull hot-path storage or umbrella dependencies into the public UDP session boundary")
    endif()
endforeach()

foreach(forbidden_storage
        "CallbackEntry"
        "CallbackIdList"
        "registered_callbacks"
        "target_to_callbacks"
        "sender_endpoint"
        "socket_"
        "last_active"
        "next_target_prune"
        "running_"
        "ThreadLocal"
        "memory::"
        "io_context_"
        "dns_service_"
        "local_port_"
        "packets_sent_"
        "packets_received_"
        "bytes_sent_"
        "bytes_received_")
    if(udp_session_header MATCHES "${forbidden_storage}")
        message(FATAL_ERROR
            "UDPSession public header must not expose callback maps, socket state, timers, counters, or Worker-local storage")
    endif()
endforeach()

if(NOT udp_session_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT udp_session_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "UDPSessionManager should hide runtime storage behind an implementation pointer")
endif()

if(NOT udp_session_cpp MATCHES "struct[ \t\r\n]+UDPSession::Impl" OR
   NOT udp_session_cpp MATCHES "ThreadLocalUnorderedMap<uint64_t, CallbackEntry>" OR
   NOT udp_session_cpp MATCHES "ThreadLocalUnorderedMap<[ \t\r\n]*UdpEndpointKey,[ \t\r\n]*CallbackIdList")
    message(FATAL_ERROR
        "UDPSession implementation should own Full Cone callback and target routing storage privately")
endif()

if(NOT udp_session_cpp MATCHES "struct[ \t\r\n]+UDPSessionManager::Impl" OR
   NOT udp_session_cpp MATCHES "ThreadLocalUnorderedMap<std::string, SessionPtr>" OR
   NOT udp_session_cpp MATCHES "ThreadLocalVector<SessionPtr>")
    message(FATAL_ERROR
        "UDPSessionManager implementation should own Worker-local session and retired-session storage privately")
endif()

if(worker_header MATCHES "udp_session_manager_")
    message(FATAL_ERROR
        "worker.hpp must not expose the UDP session manager member; keep it behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold runtime implementation details through an opaque RuntimeState pointer")
endif()

if(NOT worker_cpp MATCHES "app/udp_session\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include app/udp_session.hpp privately")
endif()

if(NOT udp_worker_cpp MATCHES "app/udp_session\\.hpp")
    message(FATAL_ERROR
        "udp_worker.cpp must include app/udp_session.hpp privately when it calls UDPSession methods")
endif()

if(NOT worker_cpp MATCHES "std::make_unique<UDPSessionManager>")
    message(FATAL_ERROR
        "Worker implementation must construct the private UDPSessionManager instance")
endif()
