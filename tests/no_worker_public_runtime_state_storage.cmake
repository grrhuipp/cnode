file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(NOT worker_header MATCHES "struct[ \t\r\n]+RuntimeState;" OR
   NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "worker.hpp must hold runtime implementation storage through an opaque RuntimeState pointer")
endif()

foreach(pattern IN ITEMS
    "runtime_snapshot"
    "io_context_"
    "StatsShard&[ \t\r\n]+stats_"
    "active_connections_[ \t\r\n]*[=;]"
    "listener_state_[ \t\r\n]*[;=]"
    "inbound_manager_[ \t\r\n]*[;=]"
    "session_tracking_[ \t\r\n]*[;=]"
    "dns_service_[ \t\r\n]*[;=]"
    "udp_session_manager_[ \t\r\n]*[;=]"
    "outbound_manager_[ \t\r\n]*[;=]"
    "router_[ \t\r\n]*[;=]"
    "rule_manager_[ \t\r\n]*[;=]"
    "dispatcher_[ \t\r\n]*[;=]")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not expose Worker runtime storage detail: ${pattern}")
    endif()
endforeach()

if(NOT worker_cpp MATCHES "struct[ \t\r\n]+Worker::RuntimeState" OR
   NOT worker_cpp MATCHES "std::atomic[ \t\r\n]*<[ \t\r\n]*std::shared_ptr[ \t\r\n]*<[ \t\r\n]*const[ \t\r\n]+WorkerRuntimeConfig" OR
   NOT worker_cpp MATCHES "net::io_context&[ \t\r\n]+io_context" OR
   NOT worker_cpp MATCHES "std::unique_ptr<ListenerState>[ \t\r\n]+listener_state" OR
   NOT worker_cpp MATCHES "std::unique_ptr<proxyman::inbound::Manager>[ \t\r\n]+inbound_manager" OR
   NOT worker_cpp MATCHES "std::unique_ptr<app::dispatcher::DefaultDispatcher>[ \t\r\n]+dispatcher")
    message(FATAL_ERROR
        "worker.cpp must privately own Worker runtime state inside Worker::RuntimeState")
endif()
