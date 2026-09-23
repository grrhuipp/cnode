if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/service/controller/node_runtime.cpp"
    CONTROL_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/bootstrap_inbounds.cpp"
    BOOTSTRAP_INBOUNDS_SOURCE)

string(FIND "${CONTROL_SOURCE}"
    "net::awaitable<void> NodeRuntime::RemoveInbound" MUTATIONS_BEGIN)
string(FIND "${CONTROL_SOURCE}"
    "net::awaitable<void> NodeRuntime::UpdateRules" MUTATIONS_END)
if(MUTATIONS_BEGIN EQUAL -1 OR MUTATIONS_END EQUAL -1 OR
   NOT MUTATIONS_BEGIN LESS MUTATIONS_END)
    message(FATAL_ERROR "could not isolate controller Worker mutations")
endif()

math(EXPR MUTATIONS_LENGTH "${MUTATIONS_END} - ${MUTATIONS_BEGIN}")
string(SUBSTRING "${CONTROL_SOURCE}"
    ${MUTATIONS_BEGIN} ${MUTATIONS_LENGTH} MUTATIONS_SOURCE)

if(MUTATIONS_SOURCE MATCHES "for[ \\t\\r\\n]*\\(")
    message(FATAL_ERROR
        "controller mutations must use the shared all-Worker batch path")
endif()

string(REGEX MATCHALL
    "RunWorkerMutationBatch" MUTATION_BATCH_CALLS "${MUTATIONS_SOURCE}")
list(LENGTH MUTATION_BATCH_CALLS MUTATION_BATCH_CALL_COUNT)
if(MUTATION_BATCH_CALL_COUNT LESS 5)
    message(FATAL_ERROR
        "remove/add inbound/outbound phases must all use Worker mutation batches")
endif()

string(FIND "${MUTATIONS_SOURCE}" "HasProxy" PROTOCOL_CHECK)
if(PROTOCOL_CHECK EQUAL -1)
    message(FATAL_ERROR
        "unsupported protocols must be rejected before inbound publication")
endif()

string(FIND "${MUTATIONS_SOURCE}" "catch (...)" FAILURE_CATCH)
if(FAILURE_CATCH EQUAL -1)
    message(FATAL_ERROR "addInbound must clean up exceptional publish failures")
endif()
string(SUBSTRING "${MUTATIONS_SOURCE}"
    ${FAILURE_CATCH} -1 FAILURE_HANDLER)
if(NOT FAILURE_HANDLER MATCHES "RemoveInbound\\(inbound.tag\\)")
    message(FATAL_ERROR
        "exceptional inbound publish failure must remove candidate state from every Worker")
endif()

# Joining after partial launch failure is verified by the allocation-fault
# cases in cnode_awaitable_batch_test, rather than matching implementation names.
