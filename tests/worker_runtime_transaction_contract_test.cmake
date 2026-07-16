if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ "${SOURCE_DIR}/src/app/worker.cpp" WORKER_SOURCE)

if(WORKER_SOURCE MATCHES "RetireInboundHandler")
    message(FATAL_ERROR
        "inbound retirement must not hide manager/slot commit ordering in a helper")
endif()

string(FIND "${WORKER_SOURCE}"
    "void Worker::UnregisterListenerOnWorkerThread" UNREGISTER_BEGIN)
string(FIND "${WORKER_SOURCE}"
    "net::awaitable<void> Worker::UnregisterListenerTask" UNREGISTER_END)
if(UNREGISTER_BEGIN EQUAL -1 OR UNREGISTER_END EQUAL -1 OR
   NOT UNREGISTER_BEGIN LESS UNREGISTER_END)
    message(FATAL_ERROR "could not isolate inbound unregister implementation")
endif()

math(EXPR UNREGISTER_LENGTH "${UNREGISTER_END} - ${UNREGISTER_BEGIN}")
string(SUBSTRING "${WORKER_SOURCE}"
    ${UNREGISTER_BEGIN} ${UNREGISTER_LENGTH} UNREGISTER_SOURCE)

function(require_step needle output_name)
    string(FIND "${UNREGISTER_SOURCE}" "${needle}" step_position)
    if(step_position EQUAL -1)
        message(FATAL_ERROR "missing inbound unregister transaction step: ${needle}")
    endif()
    set(${output_name} ${step_position} PARENT_SCOPE)
endfunction()

require_step("std::make_shared<WorkerRuntimeConfig>" SNAPSHOT_POS)
require_step("CollectTcpListenerKeys" TCP_PREPARE_POS)
require_step("CollectUdpSocketKeys" UDP_PREPARE_POS)
require_step("inbound_manager->RemoveHandler" MANAGER_COMMIT_POS)
require_step("listener_state->StopListening" TCP_COMMIT_POS)
require_step("listener_state->StopUdpListening" UDP_COMMIT_POS)
require_step("StoreSnapshot" SNAPSHOT_COMMIT_POS)

if(NOT SNAPSHOT_POS LESS TCP_PREPARE_POS OR
   NOT TCP_PREPARE_POS LESS UDP_PREPARE_POS OR
   NOT UDP_PREPARE_POS LESS MANAGER_COMMIT_POS OR
   NOT MANAGER_COMMIT_POS LESS TCP_COMMIT_POS OR
   NOT TCP_COMMIT_POS LESS UDP_COMMIT_POS OR
   NOT UDP_COMMIT_POS LESS SNAPSHOT_COMMIT_POS)
    message(FATAL_ERROR
        "inbound unregister must prepare all allocating state before committing manager, listeners, and snapshot")
endif()

if(NOT WORKER_SOURCE MATCHES
   "ListenerKeys listener_keys\\) noexcept" OR
   NOT WORKER_SOURCE MATCHES
   "ListenerKeys socket_keys\\) noexcept")
    message(FATAL_ERROR
        "prepared listener stop operations must remain non-throwing commit steps")
endif()

function(require_reuse_before_restart begin_marker end_marker reuse_marker restart_marker label)
    string(FIND "${WORKER_SOURCE}" "${begin_marker}" method_begin)
    string(FIND "${WORKER_SOURCE}" "${end_marker}" method_end)
    if(method_begin EQUAL -1 OR method_end EQUAL -1 OR
       NOT method_begin LESS method_end)
        message(FATAL_ERROR "could not isolate ${label} listener start implementation")
    endif()
    math(EXPR method_length "${method_end} - ${method_begin}")
    string(SUBSTRING "${WORKER_SOURCE}"
        ${method_begin} ${method_length} method_source)
    string(FIND "${method_source}" "${reuse_marker}" reuse_position)
    string(FIND "${method_source}" "${restart_marker}" restart_position)
    if(reuse_position EQUAL -1 OR restart_position EQUAL -1 OR
       NOT reuse_position LESS restart_position)
        message(FATAL_ERROR
            "${label} listener must reuse an unchanged socket binding before restart")
    endif()
endfunction()

require_reuse_before_restart(
    "bool Worker::ListenerState::StartListening"
    "Worker::ListenerState::CollectTcpListenerKeys"
    "UsesSameSocket"
    "StopListening"
    "TCP")
require_reuse_before_restart(
    "bool Worker::ListenerState::StartUdpListening"
    "net::awaitable<void> Worker::ListenerState::UdpReceiveLoop"
    "ReplaceHandler"
    "ResetUdpListening"
    "UDP")
