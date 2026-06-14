file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_worker.hpp" udp_worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/udp_worker.cpp" udp_worker_cpp)

if(worker_header MATCHES "app/proxyman/inbound/udp_worker\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the full UDP worker implementation header; keep UDP worker storage details private to worker.cpp")
endif()

if(worker_header MATCHES "UdpWorker")
    message(FATAL_ERROR
        "worker.hpp must not expose UdpWorker; UDP worker storage belongs behind RuntimeState/ListenerState")
endif()

if(NOT worker_cpp MATCHES "app/proxyman/inbound/udp_worker\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include the UDP worker implementation header where UDP worker internals are used")
endif()

if(udp_worker_header MATCHES "memory::" OR
   udp_worker_header MATCHES "ThreadLocal" OR
   udp_worker_header MATCHES "(udp_sockets_|retired_udp_sockets_|reply_queues_|client_sessions_|UdpSocketMap|UdpSocketPtr|UdpSocketDeleter)")
    message(FATAL_ERROR
        "udp_worker.hpp must not expose Worker-local UDP socket, reply queue, or client session containers")
endif()

if(NOT udp_worker_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*std::string[ \t\r\n]*>[ \t\r\n]+SocketKeys" OR
   NOT udp_worker_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT udp_worker_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "UdpWorker public boundary should expose ordinary socket-key DTOs and hide runtime storage behind an implementation pointer")
endif()

if(udp_worker_header MATCHES "struct[ \t\r\n]+UdpReplyQueueState" OR
   udp_worker_header MATCHES "std::deque[ \t\r\n]*<" OR
   udp_worker_header MATCHES "queued_bytes|write_in_progress|shrink_pending_on_drain|[^A-Za-z]ReplyQueue[ \t\r\n]*\\(|FindReplyQueue")
    message(FATAL_ERROR
        "udp_worker.hpp must not expose UDP reply queue storage or mutable queue internals")
endif()

if(udp_worker_header MATCHES "struct[ \t\r\n]+PendingUdpReply[ \t\r\n]*\\{" OR
   udp_worker_header MATCHES "send_buffers|PrepareSendBuffers|PayloadSize")
    message(FATAL_ERROR
        "udp_worker.hpp must expose PendingUdpReply as an opaque send handle, not reply payload or buffer internals")
endif()

if(udp_worker_header MATCHES "struct[ \t\r\n]+UdpClientSession" OR
   udp_worker_header MATCHES "UdpClientSessionMap" OR
   udp_worker_header MATCHES "std::unordered_map" OR
   udp_worker_header MATCHES "udp_dial|callback_id|last_active" OR
   udp_worker_header MATCHES "[^A-Za-z]ClientSessions[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "udp_worker.hpp must not expose UDP client session storage or mutable session fields")
endif()

if(udp_worker_header MATCHES "FindClientSession")
    message(FATAL_ERROR
        "UdpWorker public boundary should not return mutable client session pointers")
endif()

if(NOT udp_worker_header MATCHES "HasClientSession" OR
   NOT udp_worker_header MATCHES "UpsertClientSession" OR
   NOT udp_worker_header MATCHES "SendToClientSession" OR
   NOT udp_worker_header MATCHES "CleanupIdleClientSessions")
    message(FATAL_ERROR
        "UdpWorker public boundary should expose client session operations, not the session map or session fields")
endif()

if(NOT udp_worker_header MATCHES "class[ \t\r\n]+PendingUdpReply;" OR
   NOT udp_worker_header MATCHES "PendingUdpReplyPtr" OR
   NOT udp_worker_header MATCHES "ReplySendBuffers" OR
   NOT udp_worker_header MATCHES "ReplyEndpoint" OR
   NOT udp_worker_header MATCHES "EnqueueReply" OR
   NOT udp_worker_header MATCHES "BeginReplySend" OR
   NOT udp_worker_header MATCHES "CompleteReplySend")
    message(FATAL_ERROR
        "UdpWorker public boundary should expose opaque reply send operations, not queue storage")
endif()

if(NOT udp_worker_cpp MATCHES "struct[ \t\r\n]+UdpWorker::Impl" OR
   NOT udp_worker_cpp MATCHES "struct[ \t\r\n]+UdpReplyQueueState" OR
   NOT udp_worker_cpp MATCHES "class[ \t\r\n]+UdpWorker::PendingUdpReply" OR
   NOT udp_worker_cpp MATCHES "struct[ \t\r\n]+UdpClientSession" OR
   NOT udp_worker_cpp MATCHES "using[ \t\r\n]+UdpClientSessionMap" OR
   NOT udp_worker_cpp MATCHES "using[ \t\r\n]+UdpSocketPtr" OR
   NOT udp_worker_cpp MATCHES "ThreadLocalUnorderedMap<std::string,[ \t\r\n]*UdpSocketPtr" OR
   NOT udp_worker_cpp MATCHES "ThreadLocalUnorderedMap<std::string,[ \t\r\n]*UdpReplyQueueState" OR
   NOT udp_worker_cpp MATCHES "ThreadLocalUnorderedMap<std::string,[ \t\r\n]*UdpClientSessionMap")
    message(FATAL_ERROR
        "udp_worker.cpp must privately own Worker-local UDP socket, reply queue, and client session containers")
endif()
