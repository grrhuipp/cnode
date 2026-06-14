file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/dispatcher/default_dispatcher.hpp" dispatcher_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/session_tracking.hpp" session_tracking_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/traffic_types.hpp" traffic_types_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp" dispatcher_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/session_tracking.cpp" session_tracking_cpp)

foreach(public_header IN ITEMS "${worker_header}" "${dispatcher_header}")
    if(public_header MATCHES "app/session_tracking\\.hpp")
        message(FATAL_ERROR
            "Worker/DefaultDispatcher public headers must not include full session tracking storage")
    endif()
    if(public_header MATCHES "ActiveSessionMap|LocalTrafficStore")
        message(FATAL_ERROR
            "Worker/DefaultDispatcher public headers must not expose session tracking storage map types")
    endif()
endforeach()

if(worker_header MATCHES "app/traffic_types\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include traffic DTO definitions; expose UserTraffic through a forward declaration")
endif()

if(NOT worker_header MATCHES "struct[ \t\r\n]+UserTraffic;" OR
   NOT worker_header MATCHES "struct[ \t\r\n]+UserTrafficSnapshot;")
    message(FATAL_ERROR
        "worker.hpp should expose traffic collection through forward-declared traffic DTOs")
endif()

if(worker_header MATCHES "std::unordered_map[ \t\r\n]*<[ \t\r\n]*int64_t[ \t\r\n]*,[ \t\r\n]*UserTraffic" OR
   session_tracking_header MATCHES "std::unordered_map[ \t\r\n]*<[ \t\r\n]*int64_t[ \t\r\n]*,[ \t\r\n]*UserTraffic")
    message(FATAL_ERROR
        "Worker/session tracking public headers must expose UserTrafficSnapshot, not a raw unordered_map return type")
endif()

if(NOT worker_header MATCHES "net::awaitable[ \t\r\n]*<[ \t\r\n]*UserTrafficSnapshot[ \t\r\n]*>" OR
   NOT session_tracking_header MATCHES "UserTrafficSnapshot[ \t\r\n]+CollectAndResetTraffic")
    message(FATAL_ERROR
        "Worker/session tracking traffic collection must use the named UserTrafficSnapshot DTO boundary")
endif()

if(NOT traffic_types_header MATCHES "struct[ \t\r\n]+UserTrafficSnapshot" OR
   NOT traffic_types_header MATCHES "std::unordered_map[ \t\r\n]*<[ \t\r\n]*int64_t[ \t\r\n]*,[ \t\r\n]*UserTraffic[ \t\r\n]*>[ \t\r\n]+users")
    message(FATAL_ERROR
        "traffic_types.hpp should own the concrete user traffic snapshot container behind a named DTO")
endif()

if(worker_header MATCHES "session_tracking_")
    message(FATAL_ERROR
        "worker.hpp must not expose the session tracking member; keep it behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold session tracking state through an opaque RuntimeState pointer")
endif()

if(NOT dispatcher_header MATCHES "SessionTrackingState")
    message(FATAL_ERROR
        "DefaultDispatcher public boundary should bind opaque SessionTrackingState, not storage maps")
endif()

if(session_tracking_header MATCHES "#include[ \t]+\"acppnode/common/(allocator|string_hash)\\.hpp\"" OR
   session_tracking_header MATCHES "(ThreadLocal|memory::|ActiveSessionMap|LocalTrafficStore|struct[ \t\r\n]+ActiveSession|active_sessions|local_traffic)")
    message(FATAL_ERROR
        "session_tracking.hpp must expose an opaque tracking API, not Worker-local traffic/session storage")
endif()

if(NOT session_tracking_header MATCHES "class[ \t\r\n]+SessionTrackingState" OR
   NOT session_tracking_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT session_tracking_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_" OR
   NOT session_tracking_header MATCHES "CollectAndResetTraffic")
    message(FATAL_ERROR
        "SessionTrackingState should hide storage behind an implementation pointer and expose traffic collection methods")
endif()

if(NOT session_tracking_cpp MATCHES "struct[ \t\r\n]+SessionTrackingState::Impl" OR
   NOT session_tracking_cpp MATCHES "LocalTrafficStore[ \t\r\n]+local_traffic" OR
   NOT session_tracking_cpp MATCHES "ActiveSessionMap[ \t\r\n]+active_sessions")
    message(FATAL_ERROR
        "session_tracking.cpp must privately own local traffic and active session maps")
endif()

foreach(private_source IN ITEMS "${worker_cpp}" "${dispatcher_cpp}")
    if(NOT private_source MATCHES "app/session_tracking\\.hpp")
        message(FATAL_ERROR
            "Worker and DefaultDispatcher implementations must include session_tracking.hpp privately")
    endif()
endforeach()
