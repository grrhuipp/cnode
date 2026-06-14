file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/router/router.hpp" router_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/router/router.cpp" router_cpp)

if(router_header MATCHES "compound_rules_" OR
   router_header MATCHES "default_outbound_tag_" OR
   router_header MATCHES "geo_manager_" OR
   router_header MATCHES "ThreadLocal" OR
   router_header MATCHES "DomainTrie" OR
   router_header MATCHES "DomainMatcher" OR
   router_header MATCHES "IPMatcher" OR
   router_header MATCHES "Condition" OR
   router_header MATCHES "CompoundRoutingRule" OR
   router_header MATCHES "ParseCIDR" OR
   router_header MATCHES "ParseIPv4" OR
   router_header MATCHES "#include[ \t]+\"acppnode/common" OR
   router_header MATCHES "#include[ \t]+\"acppnode/infra/config_types\\.hpp\"" OR
   router_header MATCHES "#include[ \t]+<regex>" OR
   router_header MATCHES "#include[ \t]+<variant>" OR
   router_header MATCHES "#include[ \t]+<vector>")
    message(FATAL_ERROR
        "Router public header must not expose matcher/runtime storage types or heavy implementation dependencies")
endif()

if(NOT router_header MATCHES "struct Impl;" OR
   NOT router_header MATCHES "std::unique_ptr<Impl>")
    message(FATAL_ERROR
        "Router must hide runtime storage behind a private implementation boundary")
endif()

if(NOT router_cpp MATCHES "ThreadLocalVector<CompoundRoutingRule>" OR
   NOT router_cpp MATCHES "default_outbound_tag" OR
   NOT router_cpp MATCHES "geo_manager")
    message(FATAL_ERROR
        "Router implementation must own the runtime rule/default/geo manager storage details")
endif()
