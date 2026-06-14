file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/service/controller/controller.hpp" controller_header)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/controller_impl.hpp" controller_impl)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/controller.cpp" controller_source)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_control)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/userbuilder.cpp" controller_userbuilder)

foreach(pattern
    "#include[ \t]+\"acppnode/common\\.hpp\""
    "#include[ \t]+\"acppnode/api/api\\.hpp\""
    "#include[ \t]+\"acppnode/service/controller/config\\.hpp\""
    "net::awaitable"
    "runNodeInfoMonitors"
    "nodeInfoMonitor"
    "userInfoMonitor"
    "getTraffic"
    "GetOnlineDevice"
    "GetDetectResult"
    "BuildVmessUsers"
    "BuildTrojanUsers"
    "BuildShadowsocksUsers"
    "BuildUsersForInbound"
    "std::map<"
    "std::unordered_set<"
    "panel_configs_"
    "node_configs_"
    "user_lists_"
    "inbound_started_"
    "ban_tracking_tags_"
    "workers_"
    "limiters_")
    if(controller_header MATCHES "${pattern}")
        message(FATAL_ERROR "Controller public header must not expose panel sync runtime state or builder internals: ${pattern}")
    endif()
endforeach()

if(NOT controller_header MATCHES "#include[ \t]+\"acppnode/common/asio_types\\.hpp\"" OR
   NOT controller_header MATCHES "struct[ \t\r\n]+Impl" OR
   NOT controller_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR "Controller public header must expose a narrow PImpl API over asio types only")
endif()

foreach(required
    "struct[ \t\r\n]+Controller::Impl"
    "runNodeInfoMonitors"
    "nodeInfoMonitor"
    "userInfoMonitor"
    "getTraffic"
    "GetOnlineDevice"
    "GetDetectResult"
    "BuildUsersForInbound"
    "std::map<api::API\\*,[ \t\r\n]*PanelConfig>"
    "std::map<api::API\\*,[ \t\r\n]*api::NodeInfo>"
    "std::map<api::API\\*,[ \t\r\n]*std::vector<api::UserInfo>[ \t\r\n]*>"
    "std::unordered_set<std::string>")
    if(NOT controller_impl MATCHES "${required}")
        message(FATAL_ERROR "Controller private impl header must own panel sync state and cold-path helpers: ${required}")
    endif()
endforeach()

if(NOT controller_source MATCHES "impl_[ \t\r\n]*\\([ \t\r\n]*std::make_unique<Impl>" OR
   NOT controller_source MATCHES "Controller::Impl::runNodeInfoMonitors" OR
   NOT controller_control MATCHES "Controller::Impl::getTraffic" OR
   NOT controller_userbuilder MATCHES "Controller::Impl::BuildUsersForInbound")
    message(FATAL_ERROR "Controller implementation files must route public API through private Impl")
endif()
