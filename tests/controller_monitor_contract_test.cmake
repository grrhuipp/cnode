if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ "${SOURCE_DIR}/include/acppnode/service/controller/controller.hpp" CONTROLLER_HEADER)
file(READ "${SOURCE_DIR}/src/service/controller/controller.cpp" CONTROLLER_SOURCE)
file(READ "${SOURCE_DIR}/src/service/controller/controller_impl.hpp" CONTROLLER_IMPL)
file(READ "${SOURCE_DIR}/include/acppnode/api/api.hpp" API_HEADER)
file(READ "${SOURCE_DIR}/src/api/v2board/v2board.cpp" V2BOARD_SOURCE)

foreach(REQUIRED_HEADER
        "std::shared_ptr<Impl> impl_;"
        "Controller(Controller&&) = delete")
    string(FIND "${CONTROLLER_HEADER}" "${REQUIRED_HEADER}" REQUIRED_POSITION)
    if(REQUIRED_POSITION EQUAL -1)
        message(FATAL_ERROR "Controller lifetime boundary is missing '${REQUIRED_HEADER}'")
    endif()
endforeach()

if(CONTROLLER_HEADER MATCHES "Stop[(]" OR
   CONTROLLER_IMPL MATCHES "Stop[(]|monitor_generation_|monitor_completion_|CancelableTimerRegistry|panel_nodes_" OR
   CONTROLLER_SOURCE MATCHES "RunAwaitableBatch|runPanelMonitors|running_|monitors_active_" OR
   API_HEADER MATCHES "CancelPending" OR
   V2BOARD_SOURCE MATCHES "CancelPending|ActiveSocketRegistration|active_sockets_|cancel_epoch_")
    message(FATAL_ERROR "unused Controller shutdown APIs and their supporting state must stay removed")
endif()

if(EXISTS "${SOURCE_DIR}/src/common/cancelable_timer_registry.hpp")
    message(FATAL_ERROR "the unused timer cancellation registry must stay removed")
endif()

if(NOT CONTROLLER_IMPL MATCHES "std::weak_ptr<monitor_detail::MonitorLoop>" OR
   NOT CONTROLLER_SOURCE MATCHES "self->panelSyncLoop[(][*]panel[)]" OR
   NOT CONTROLLER_SOURCE MATCHES "self->panelStatusLoop[(][*]panel[)]" OR
   NOT CONTROLLER_SOURCE MATCHES "monitor_detail::MonitorLoop" OR
   NOT CONTROLLER_SOURCE MATCHES "slot.expired[(][)]" OR
   NOT CONTROLLER_SOURCE MATCHES "Panel [{][}] monitor: failed")
    message(FATAL_ERROR "panel loops must independently retain their owner and report exits without an ownership cycle")
endif()

if(CONTROLLER_IMPL MATCHES "panel_configs_|panel_states_|committed_nodes_|node_stats_|PanelMonitor" OR
   CONTROLLER_SOURCE MATCHES "ResolvePanelName|Describe[(]" OR
   API_HEADER MATCHES "ClientInfo|Describe[(]" OR
   NOT CONTROLLER_IMPL MATCHES "std::vector<std::unique_ptr<PanelRuntime>> panels_" OR
   NOT CONTROLLER_IMPL MATCHES "const PanelConfig config")
    message(FATAL_ERROR "each panel must own its immutable config, client, committed state and statistics")
endif()
