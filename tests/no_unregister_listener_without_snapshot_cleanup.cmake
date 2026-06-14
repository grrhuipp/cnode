file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)

if(NOT worker_source MATCHES "RemoveInboundRuntimeFromSnapshot")
    message(FATAL_ERROR
        "worker.cpp must provide a helper that removes unregistered inbound runtime entries from WorkerRuntimeConfig")
endif()

string(FIND "${worker_source}" "void Worker::UnregisterListenerAsync" method_start)
if(method_start EQUAL -1)
    message(FATAL_ERROR "Worker::UnregisterListenerAsync implementation is missing")
endif()

string(FIND "${worker_source}" "void Worker::EnableBanTrackingAsync" method_end)
if(method_end EQUAL -1)
    message(FATAL_ERROR "Worker::EnableBanTrackingAsync marker is missing")
endif()

math(EXPR body_length "${method_end} - ${method_start}")
string(SUBSTRING "${worker_source}" ${method_start} ${body_length} method_body)

foreach(required
        "runtime_->Snapshot"
        "runtime_->listener_state->StopListening"
        "runtime_->listener_state->StopUdpListening"
        "runtime_->listener_state->RetireInboundHandler"
        "RemoveInboundRuntimeFromSnapshot"
        "runtime_->StoreSnapshot")
    if(NOT method_body MATCHES "${required}")
        message(FATAL_ERROR
            "Worker::UnregisterListenerAsync must ${required} when unregistering an inbound listener")
    endif()
endforeach()

string(FIND "${method_body}" "runtime_->listener_state->RetireInboundHandler" retire_pos)
string(FIND "${method_body}" "RemoveInboundRuntimeFromSnapshot" cleanup_pos)
string(FIND "${method_body}" "runtime_->StoreSnapshot" store_pos)

if(retire_pos EQUAL -1 OR cleanup_pos EQUAL -1 OR store_pos EQUAL -1 OR
   NOT retire_pos LESS cleanup_pos OR NOT cleanup_pos LESS store_pos)
    message(FATAL_ERROR
        "Worker::UnregisterListenerAsync must retire the handler, clean runtime inbound entries, then publish the snapshot")
endif()
