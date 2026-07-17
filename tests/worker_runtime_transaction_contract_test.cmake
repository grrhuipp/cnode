if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ "${SOURCE_DIR}/src/app/worker.cpp" WORKER_SOURCE)
file(READ "${SOURCE_DIR}/src/app/bootstrap_runtime.cpp" BOOTSTRAP_RUNTIME_SOURCE)
file(READ "${SOURCE_DIR}/src/app/bootstrap_inbounds.cpp" BOOTSTRAP_INBOUNDS_SOURCE)

string(FIND "${WORKER_SOURCE}" "Worker::Worker(" WORKER_CTOR_BEGIN)
string(FIND "${WORKER_SOURCE}" "Worker::~Worker" WORKER_CTOR_END)
if(WORKER_CTOR_BEGIN EQUAL -1 OR WORKER_CTOR_END EQUAL -1 OR
   NOT WORKER_CTOR_BEGIN LESS WORKER_CTOR_END)
    message(FATAL_ERROR "could not isolate Worker constructor")
endif()
math(EXPR WORKER_CTOR_LENGTH "${WORKER_CTOR_END} - ${WORKER_CTOR_BEGIN}")
string(SUBSTRING "${WORKER_SOURCE}"
    ${WORKER_CTOR_BEGIN} ${WORKER_CTOR_LENGTH} WORKER_CTOR_SOURCE)
if(WORKER_CTOR_SOURCE MATCHES
       "StartCleanup[(][)]|InitOutbounds[(]|InitRouter[(]|BindOutboundManager[(]" OR
   NOT WORKER_SOURCE MATCHES
       "Worker::StartRuntimeTask[(][)]")
    message(FATAL_ERROR
        "Worker construction must not build or start Worker-local runtime state")
endif()

string(FIND "${BOOTSTRAP_RUNTIME_SOURCE}"
    "TimeoutScheduler::ForIoContext(*ctx.io_contexts[i])" SCHEDULER_START_POS)
string(FIND "${BOOTSTRAP_RUNTIME_SOURCE}"
    "ctx.io_contexts[i]->run()" WORKER_RUN_POS)
string(FIND "${BOOTSTRAP_RUNTIME_SOURCE}"
    "TimeoutScheduler::ReleaseForIoContext(*ctx.io_contexts[i])" SCHEDULER_RELEASE_POS)
if(SCHEDULER_START_POS EQUAL -1 OR WORKER_RUN_POS EQUAL -1 OR
   SCHEDULER_RELEASE_POS EQUAL -1 OR
   NOT SCHEDULER_START_POS LESS WORKER_RUN_POS OR
   NOT WORKER_RUN_POS LESS SCHEDULER_RELEASE_POS)
    message(FATAL_ERROR
        "Worker scheduler must start and release inside the owning Worker thread")
endif()

string(FIND "${BOOTSTRAP_INBOUNDS_SOURCE}"
    "co_await worker.StartRuntimeTask()" WORKER_RUNTIME_START_POS)
string(FIND "${BOOTSTRAP_INBOUNDS_SOURCE}"
    "co_await worker.RegisterInboundTask(" WORKER_INBOUND_START_POS)
if(WORKER_RUNTIME_START_POS EQUAL -1 OR WORKER_INBOUND_START_POS EQUAL -1 OR
   NOT WORKER_RUNTIME_START_POS LESS WORKER_INBOUND_START_POS OR
   BOOTSTRAP_INBOUNDS_SOURCE MATCHES
       "if [(]startup.entries.empty[(][)][)]")
    message(FATAL_ERROR
        "every Worker must build its runtime before static inbound registration")
endif()

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

string(FIND "${WORKER_SOURCE}"
    "bool Worker::ListenerState::StartUdpListening" UDP_START_BEGIN)
string(FIND "${WORKER_SOURCE}"
    "net::awaitable<void> Worker::ListenerState::UdpReceiveLoop" UDP_START_END)
math(EXPR UDP_START_LENGTH "${UDP_START_END} - ${UDP_START_BEGIN}")
string(SUBSTRING "${WORKER_SOURCE}"
    ${UDP_START_BEGIN} ${UDP_START_LENGTH} UDP_START_SOURCE)
string(FIND "${UDP_START_SOURCE}"
    "if (bound_count == 0)" UDP_BIND_FAILURE_POS)
string(FIND "${UDP_START_SOURCE}"
    "ResetUdpListening" UDP_REPLACE_COMMIT_POS)
string(FIND "${UDP_START_SOURCE}"
    "worker_it->second = std::move(replacement_worker)" UDP_WORKER_COMMIT_POS)
string(FIND "${UDP_START_SOURCE}"
    "net::co_spawn" UDP_RECEIVE_START_POS)
if(UDP_BIND_FAILURE_POS EQUAL -1 OR UDP_REPLACE_COMMIT_POS EQUAL -1 OR
   UDP_WORKER_COMMIT_POS EQUAL -1 OR UDP_RECEIVE_START_POS EQUAL -1 OR
   NOT UDP_BIND_FAILURE_POS LESS UDP_REPLACE_COMMIT_POS OR
   NOT UDP_REPLACE_COMMIT_POS LESS UDP_WORKER_COMMIT_POS OR
   NOT UDP_WORKER_COMMIT_POS LESS UDP_RECEIVE_START_POS)
    message(FATAL_ERROR
        "UDP listener replacement must bind before retiring the live worker and start receive loops only after commit")
endif()
