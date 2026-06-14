file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/dispatcher/default_dispatcher.hpp" dispatcher_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp" dispatcher_source)

if(dispatcher_header MATCHES "common/rule\\.hpp")
    message(FATAL_ERROR
        "default_dispatcher.hpp must not include the full rule manager implementation header; forward declare rule::Manager")
endif()

if(NOT dispatcher_header MATCHES "namespace[ \t\r\n]+rule[ \t\r\n]*\\{[ \t\r\n]*class[ \t\r\n]+Manager;")
    message(FATAL_ERROR
        "default_dispatcher.hpp must forward declare rule::Manager for pointer/reference binding")
endif()

if(NOT dispatcher_source MATCHES "common/rule\\.hpp")
    message(FATAL_ERROR
        "default_dispatcher.cpp must include common/rule.hpp directly when it calls rule::Manager")
endif()
