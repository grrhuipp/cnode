file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/factory.hpp" factory_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/factory.cpp" factory_source)

if(factory_header MATCHES "infra/json\\.hpp" OR
   factory_header MATCHES "json::object" OR
   factory_header MATCHES "build_static_users[\\s\\S]*settings" OR
   factory_header MATCHES "BuildStaticUsers[\\s\\S]*settings")
    message(FATAL_ERROR
        "proxyman inbound factory public API must not expose raw JSON settings; normalize static user config in the cold path")
endif()

if(factory_source MATCHES "json::object")
    message(FATAL_ERROR
        "proxyman inbound factory implementation must not receive raw JSON settings")
endif()
