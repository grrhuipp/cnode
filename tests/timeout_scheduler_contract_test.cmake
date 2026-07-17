if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/transport/internet/timeout_scheduler.cpp"
    SCHEDULER_SOURCE)

if(NOT SCHEDULER_SOURCE MATCHES
       "kHeapCompactStaleFloor = 1024" OR
   NOT SCHEDULER_SOURCE MATCHES
       "stale < deadline_heap.size[(][)] / 2" OR
   NOT SCHEDULER_SOURCE MATCHES
       "void MaybeCompactHeap[(][)] noexcept" OR
   NOT SCHEDULER_SOURCE MATCHES
       "dispatching_ready_batch")
    message(FATAL_ERROR
        "cancelled timeout heap entries must remain bounded by proportional compaction")
endif()

string(FIND "${SCHEDULER_SOURCE}"
    "void MaybeCompactHeap() noexcept" COMPACT_BEGIN)
string(FIND "${SCHEDULER_SOURCE}"
    "void ArmTimer()" COMPACT_END)
if(COMPACT_BEGIN EQUAL -1 OR COMPACT_END EQUAL -1 OR
   NOT COMPACT_BEGIN LESS COMPACT_END)
    message(FATAL_ERROR "could not isolate timeout heap compaction")
endif()
math(EXPR COMPACT_LENGTH "${COMPACT_END} - ${COMPACT_BEGIN}")
string(SUBSTRING "${SCHEDULER_SOURCE}"
    ${COMPACT_BEGIN} ${COMPACT_LENGTH} COMPACT_SOURCE)
if(NOT COMPACT_SOURCE MATCHES "try [{]" OR
   NOT COMPACT_SOURCE MATCHES "catch [(]...[)]" OR
   NOT COMPACT_SOURCE MATCHES "deadline_heap.swap[(]compacted[)]")
    message(FATAL_ERROR
        "timeout heap compaction must be transactional and non-throwing")
endif()

string(FIND "${SCHEDULER_SOURCE}"
    "void TimeoutScheduler::Cancel" CANCEL_BEGIN)
string(FIND "${SCHEDULER_SOURCE}"
    "ScheduledSleep::ScheduledSleep" CANCEL_END)
if(CANCEL_BEGIN EQUAL -1 OR CANCEL_END EQUAL -1 OR
   NOT CANCEL_BEGIN LESS CANCEL_END)
    message(FATAL_ERROR "could not isolate timeout cancellation")
endif()
math(EXPR CANCEL_LENGTH "${CANCEL_END} - ${CANCEL_BEGIN}")
string(SUBSTRING "${SCHEDULER_SOURCE}"
    ${CANCEL_BEGIN} ${CANCEL_LENGTH} CANCEL_SOURCE)
if(NOT CANCEL_SOURCE MATCHES "impl_->MaybeCompactHeap[(][)]")
    message(FATAL_ERROR
        "cancellation must reclaim non-top deadline heap tombstones")
endif()
