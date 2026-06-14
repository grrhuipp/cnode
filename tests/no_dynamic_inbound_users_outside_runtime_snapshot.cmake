file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_runtime_config.hpp" worker_runtime_config)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_source)

if(NOT worker_runtime_config MATCHES "struct[ \t\r\n]+InboundUsersRuntimeEntry" OR
   NOT worker_runtime_config MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*InboundUsersRuntimeEntry[ \t\r\n]*>[ \t\r\n]+inbound_users")
    message(FATAL_ERROR
        "WorkerRuntimeConfig must carry prepared inbound users so dynamic panel user updates are represented in the immutable runtime snapshot")
endif()

function(require_snapshot_update method next_method manager_call snapshot_helper)
    string(FIND "${worker_source}" "void Worker::${method}" method_start)
    if(method_start EQUAL -1)
        message(FATAL_ERROR "Worker ${method} implementation is missing")
    endif()

    string(FIND "${worker_source}" "void Worker::${next_method}" method_end)
    if(method_end EQUAL -1)
        message(FATAL_ERROR "Worker ${next_method} marker is missing")
    endif()

    math(EXPR body_length "${method_end} - ${method_start}")
    string(SUBSTRING "${worker_source}" ${method_start} ${body_length} method_body)

    string(FIND "${method_body}" "${manager_call}" manager_pos)
    string(FIND "${method_body}" "${snapshot_helper}" helper_pos)
    string(FIND "${method_body}" "StoreSnapshot" store_pos)

    if(manager_pos EQUAL -1 OR helper_pos EQUAL -1 OR store_pos EQUAL -1)
        message(FATAL_ERROR
            "Worker ${method} must apply the Worker-local validator change, update prepared inbound users, and replace WorkerRuntimeConfig snapshot")
    endif()

    if(NOT manager_pos LESS helper_pos OR NOT helper_pos LESS store_pos)
        message(FATAL_ERROR
            "Worker ${method} must apply the Worker-local validator change before publishing the runtime snapshot")
    endif()
endfunction()

require_snapshot_update(
    "ApplyInboundUsersAsync"
    "AddInboundUsersAsync"
    "runtime_->inbound_manager->ApplyUsers"
    "ApplyInboundUsersToSnapshot")
require_snapshot_update(
    "AddInboundUsersAsync"
    "RemoveInboundUsersAsync"
    "runtime_->inbound_manager->AddUsers"
    "AddInboundUsersToSnapshot")
require_snapshot_update(
    "RemoveInboundUsersAsync"
    "ClearInboundUsersAsync"
    "runtime_->inbound_manager->RemoveUsers"
    "RemoveInboundUsersFromSnapshot")
require_snapshot_update(
    "ClearInboundUsersAsync"
    "UnregisterListenerAsync"
    "runtime_->inbound_manager->ClearUsers"
    "ClearInboundUsersFromSnapshot")
