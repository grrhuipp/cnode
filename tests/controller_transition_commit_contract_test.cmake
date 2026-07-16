if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/service/controller/controller.cpp"
    CONTROLLER_SOURCE)
file(READ
    "${SOURCE_DIR}/src/service/controller/node_transition.hpp"
    TRANSITION_HEADER)
file(READ
    "${SOURCE_DIR}/src/service/controller/controller_impl.hpp"
    CONTROLLER_HEADER)

if(TRANSITION_HEADER MATCHES "RetireOldAfterCommit")
    message(FATAL_ERROR
        "old tag retirement must not be modeled as a post-commit action")
endif()
if(TRANSITION_HEADER MATCHES "RestoreOldInboundOnRollback")
    message(FATAL_ERROR
        "rollback restoration must follow actual mutation progress, not a static transition mode")
endif()
if(NOT TRANSITION_HEADER MATCHES "RetireOldInboundBeforeCommit")
    message(FATAL_ERROR
        "transition plan must expose pre-commit old inbound retirement")
endif()

string(FIND "${CONTROLLER_SOURCE}"
    "std::exception_ptr transition_failure" TRANSITION_BEGIN)
string(FIND "${CONTROLLER_SOURCE}"
    "node config_committed" TRANSITION_END)
if(TRANSITION_BEGIN EQUAL -1 OR TRANSITION_END EQUAL -1 OR
   NOT TRANSITION_BEGIN LESS TRANSITION_END)
    message(FATAL_ERROR "could not isolate candidate transition commit path")
endif()

math(EXPR TRANSITION_LENGTH "${TRANSITION_END} - ${TRANSITION_BEGIN}")
string(SUBSTRING "${CONTROLLER_SOURCE}"
    ${TRANSITION_BEGIN} ${TRANSITION_LENGTH} TRANSITION_SOURCE)

string(FIND "${TRANSITION_SOURCE}"
    "removeOutbound(old_tag)" OLD_OUTBOUND_CLEANUP)
string(FIND "${TRANSITION_SOURCE}"
    "UpdateRule(old_tag, {})" OLD_RULE_CLEANUP)
string(FIND "${TRANSITION_SOURCE}"
    "UpdateRule(tag, rules_result.rules)" NEW_RULE_COMMIT)
string(FIND "${TRANSITION_SOURCE}"
    "committed_nodes_.insert_or_assign" CONFIG_COMMIT)
string(FIND "${TRANSITION_SOURCE}"
    "catch (...)" TRANSITION_CATCH)
string(FIND "${TRANSITION_SOURCE}"
    "co_await rollback()" ROLLBACK_CALL)

# The normalized rule snapshot is named next_rules before entering the
# transition, so publish that snapshot rather than the raw fetch result.
if(NEW_RULE_COMMIT EQUAL -1)
    string(FIND "${TRANSITION_SOURCE}"
        "UpdateRule(tag, *next_rules)" NEW_RULE_COMMIT)
endif()

if(OLD_OUTBOUND_CLEANUP EQUAL -1 OR OLD_RULE_CLEANUP EQUAL -1 OR
   NEW_RULE_COMMIT EQUAL -1 OR CONFIG_COMMIT EQUAL -1 OR
   TRANSITION_CATCH EQUAL -1 OR ROLLBACK_CALL EQUAL -1)
    message(FATAL_ERROR "candidate transition is missing a required commit step")
endif()
if(NOT OLD_OUTBOUND_CLEANUP LESS OLD_RULE_CLEANUP OR
   NOT OLD_RULE_CLEANUP LESS NEW_RULE_COMMIT OR
   NOT NEW_RULE_COMMIT LESS CONFIG_COMMIT OR
   NOT CONFIG_COMMIT LESS TRANSITION_CATCH OR
   NOT TRANSITION_CATCH LESS ROLLBACK_CALL)
    message(FATAL_ERROR
        "all runtime mutations must finish before the single state commit and remain inside rollback scope")
endif()

if(CONTROLLER_HEADER MATCHES "node_configs_" OR
   CONTROLLER_HEADER MATCHES "user_lists_" OR
   CONTROLLER_HEADER MATCHES "inbound_started_" OR
   NOT CONTROLLER_HEADER MATCHES "CommittedNodeState" OR
   NOT CONTROLLER_HEADER MATCHES "std::vector<api::DetectRule> rules")
    message(FATAL_ERROR
        "controller config, users, rules, and inbound state must share one committed record")
endif()
