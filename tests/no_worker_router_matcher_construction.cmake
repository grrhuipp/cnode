file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/router/router.cpp" router_cpp)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/router/router.hpp" router_header)

foreach(name IN ITEMS CompoundRoutingRule DomainMatcher IPMatcher DomainCondition IPCondition GeoSiteCondition GeoIPCondition SourceIPCondition)
    if(worker_cpp MATCHES "${name}")
        message(FATAL_ERROR
            "Worker must not construct Router matcher internals directly: ${name}")
    endif()
endforeach()

if(NOT worker_cpp MATCHES "router(\\.|->)Configure[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Worker must delegate routing runtime construction to Router::Configure")
endif()

if(router_header MATCHES "proxyman")
    message(FATAL_ERROR
        "Router public header must not depend on proxyman types for routing runtime construction")
endif()

if(NOT router_header MATCHES "void Configure[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Router must expose a cold-path Configure boundary for routing runtime construction")
endif()

if(NOT router_cpp MATCHES "CompoundRoutingRule" OR
   NOT router_cpp MATCHES "DomainMatcher" OR
   NOT router_cpp MATCHES "IPMatcher")
    message(FATAL_ERROR
        "Router implementation must own routing matcher construction")
endif()
