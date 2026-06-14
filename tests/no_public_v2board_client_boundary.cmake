set(public_v2board_header "${PROJECT_SOURCE_DIR}/include/acppnode/api/v2board/v2board.hpp")
if(EXISTS "${public_v2board_header}")
    message(FATAL_ERROR "Concrete V2Board client header must not be part of the public API boundary")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/api/panel_factory.hpp" panel_factory_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_panels.cpp" bootstrap_panels_source)
file(READ "${PROJECT_SOURCE_DIR}/src/api/v2board/v2board.cpp" v2board_source)

if(NOT panel_factory_header MATCHES "CreatePanelClient" OR
   panel_factory_header MATCHES "v2board|V2Board|APIClient")
    message(FATAL_ERROR "Public panel factory must expose only generic panel client creation")
endif()

if(bootstrap_panels_source MATCHES "api/v2board/v2board\\.hpp" OR
   bootstrap_panels_source MATCHES "api::v2board" OR
   bootstrap_panels_source MATCHES "v2board::New" OR
   NOT bootstrap_panels_source MATCHES "api/panel_factory\\.hpp" OR
   NOT bootstrap_panels_source MATCHES "CreatePanelClient")
    message(FATAL_ERROR "Bootstrap panel setup must use the generic panel factory, not the concrete V2Board client")
endif()

if(NOT v2board_source MATCHES "class[ \t\r\n]+APIClient[ \t\r\n]+final" OR
   NOT v2board_source MATCHES "CreatePanelClient")
    message(FATAL_ERROR "V2Board client class should be private to the implementation file behind CreatePanelClient")
endif()
