if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ "${SOURCE_DIR}/src/service/controller/controller.cpp" CONTROLLER_SOURCE)
file(READ "${SOURCE_DIR}/src/service/controller/node_transition.hpp" TRANSITION_HEADER)
file(READ "${SOURCE_DIR}/src/service/controller/node_state.hpp" STATE_HEADER)
file(READ "${SOURCE_DIR}/src/service/controller/node_transaction.hpp" TRANSACTION_HEADER)

if(TRANSITION_HEADER MATCHES "RetireOldAfterCommit|RestoreOldInboundOnRollback" OR
   NOT TRANSITION_HEADER MATCHES "RetireOldInboundBeforeCommit")
    message(FATAL_ERROR "old runtime retirement and rollback must follow actual mutation progress")
endif()

if(STATE_HEADER MATCHES "inbound_started" OR
   NOT STATE_HEADER MATCHES "std::shared_ptr<const NodeSnapshot> committed" OR
   NOT STATE_HEADER MATCHES "NodeRuntimePhase" OR
   NOT STATE_HEADER MATCHES "pending_cleanup" OR
   NOT STATE_HEADER MATCHES "std::vector<api::DetectRule> rules")
    message(FATAL_ERROR "immutable committed data, runtime health and unfinished cleanup must have distinct state")
endif()

if(CONTROLLER_SOURCE MATCHES "UserStore::ApplyUsers|removeInbound|clearUsers|co_await rollback" OR
   NOT CONTROLLER_SOURCE MATCHES "controller::ApplyNodeChange" OR
   NOT CONTROLLER_SOURCE MATCHES "controller::RemoveNode" OR
   NOT TRANSACTION_HEADER MATCHES "CleanPendingNodeRuntime")
    message(FATAL_ERROR "node mutation and rollback orchestration must belong to the shared private transaction")
endif()

# Mutation ordering, partial effects, incomplete rollback, removal and recovery
# are exercised by cnode_node_transaction_test with concrete operation failures.
