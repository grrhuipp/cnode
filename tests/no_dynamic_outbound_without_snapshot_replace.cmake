file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)

if(worker_header MATCHES "StoreRuntimeSnapshot" OR worker_header MATCHES "StoreSnapshot")
    message(FATAL_ERROR
        "worker.hpp must not expose runtime snapshot replacement helpers")
endif()

if(NOT worker_source MATCHES "StoreSnapshot")
    message(FATAL_ERROR
        "Worker RuntimeState snapshot replacement helper must be implemented")
endif()

if(NOT worker_source MATCHES "runtime_snapshot\\.store")
    message(FATAL_ERROR
        "Worker runtime snapshot replacement helper must atomically store the new snapshot")
endif()

if(NOT worker_source MATCHES "void[ \t\r\n]+Worker::AddOutboundAsync" OR
   NOT worker_source MATCHES "next_snapshot->outbounds\\.push_back")
    message(FATAL_ERROR
        "Dynamic outbound add must replace WorkerRuntimeConfig snapshot after installing the handler")
endif()

if(NOT worker_source MATCHES "void[ \t\r\n]+Worker::RemoveOutboundAsync" OR
   NOT worker_source MATCHES "std::erase_if\\(next_snapshot->outbounds")
    message(FATAL_ERROR
        "Dynamic outbound remove must replace WorkerRuntimeConfig snapshot after removing the handler")
endif()

string(REGEX MATCHALL "StoreSnapshot" snapshot_store_calls "${worker_source}")
list(LENGTH snapshot_store_calls snapshot_store_call_count)
if(snapshot_store_call_count LESS 3)
    message(FATAL_ERROR
        "Dynamic outbound add/remove must both store a replacement runtime snapshot")
endif()
