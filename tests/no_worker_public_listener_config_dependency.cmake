file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

foreach(pattern IN ITEMS
    "app/port_binding\\.hpp"
    "app/proxyman/inbound/receiver_settings\\.hpp"
    "void[ \t\r\n]+AddListenerAsync\\(PortBinding"
    "void[ \t\r\n]+AddUdpListenerAsync\\(PortBinding"
    "void[ \t\r\n]+RegisterListenerAsync\\(proxyman::inbound::ReceiverSettings[ \t\r\n]+receiver")
    if(worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp must not expose full listener config storage by value/include: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "struct[ \t\r\n]+PortBinding;"
    "struct[ \t\r\n]+ReceiverSettings;"
    "AddListenerAsync\\(const[ \t\r\n]+PortBinding&"
    "AddUdpListenerAsync\\(const[ \t\r\n]+PortBinding&"
    "RegisterListenerAsync\\(proxyman::inbound::ReceiverSettings&&")
    if(NOT worker_header MATCHES "${pattern}")
        message(FATAL_ERROR
            "worker.hpp should expose listener config through forward-declared reference boundaries: ${pattern}")
    endif()
endforeach()

if(NOT worker_cpp MATCHES "app/port_binding\\.hpp" OR
   NOT worker_cpp MATCHES "app/proxyman/inbound/receiver_settings\\.hpp")
    message(FATAL_ERROR
        "worker.cpp must include full listener config definitions where async registration copies them")
endif()
