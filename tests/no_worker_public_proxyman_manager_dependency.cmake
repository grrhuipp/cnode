file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(manager_header IN ITEMS
    "app/proxyman/inbound/manager\\.hpp"
    "app/proxyman/outbound/manager\\.hpp")
    if(worker_header MATCHES "${manager_header}")
        message(FATAL_ERROR
            "worker.hpp must not include proxyman manager implementation boundary: ${manager_header}")
    endif()
endforeach()

if(worker_header MATCHES "proxyman::inbound::Manager[ \t\r\n]+inbound_manager_" OR
   worker_header MATCHES "proxyman::outbound::Manager[ \t\r\n]+outbound_manager_")
    message(FATAL_ERROR
        "Worker public header must not store proxyman managers by value")
endif()

if(worker_header MATCHES "inbound_manager_" OR worker_header MATCHES "outbound_manager_")
    message(FATAL_ERROR
        "worker.hpp must not expose proxyman manager members; keep them behind RuntimeState")
endif()

if(NOT worker_header MATCHES "std::unique_ptr<RuntimeState>[ \t\r\n]+runtime_")
    message(FATAL_ERROR
        "Worker should hold proxyman managers through an opaque RuntimeState pointer")
endif()

foreach(manager_header IN ITEMS
    "app/proxyman/inbound/manager\\.hpp"
    "app/proxyman/outbound/manager\\.hpp")
    if(NOT worker_cpp MATCHES "${manager_header}")
        message(FATAL_ERROR
            "worker.cpp must include proxyman manager headers privately: ${manager_header}")
    endif()
endforeach()

if(NOT worker_cpp MATCHES "std::make_unique<proxyman::inbound::Manager>" OR
   NOT worker_cpp MATCHES "std::make_unique<proxyman::outbound::Manager>")
    message(FATAL_ERROR
        "Worker implementation must construct private proxyman manager instances")
endif()
