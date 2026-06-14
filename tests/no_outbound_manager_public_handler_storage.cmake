file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/outbound/manager.hpp" manager_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/outbound/manager.cpp" manager_cpp)

if(manager_header MATCHES "common/(allocator|string_hash)\\.hpp")
    message(FATAL_ERROR
        "proxyman outbound manager public header must not expose Worker-local storage helper dependencies")
endif()

if(manager_header MATCHES "(ThreadLocalUnorderedMap|ThreadLocalVector|retired_handlers_|default_handler_|HandlerMap)")
    message(FATAL_ERROR
        "proxyman outbound manager public header must not expose handler map or retired-handler storage")
endif()

if(NOT manager_header MATCHES "struct Impl;")
    message(FATAL_ERROR
        "proxyman outbound manager must hide handler storage behind a private implementation boundary")
endif()

if(NOT manager_cpp MATCHES "ThreadLocalUnorderedMap" OR
   NOT manager_cpp MATCHES "retired_handlers")
    message(FATAL_ERROR
        "proxyman outbound manager implementation must own the handler storage details")
endif()
