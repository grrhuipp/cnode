set(relay_headers
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/relay.hpp"
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/relay_types.hpp"
)

foreach(file IN LISTS relay_headers)
    file(READ "${file}" content)
    if(content MATCHES "Wrapper|wrapper|RelayWrapper|WrapRelay|relay[ _-]wrapper")
        message(FATAL_ERROR "Relay wrapper API remains in ${file}")
    endif()
endforeach()
