file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/rule.hpp" rule_header)
file(READ "${PROJECT_SOURCE_DIR}/src/common/rule.cpp" rule_source)

if(NOT rule_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT rule_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "rule::Manager public header must keep runtime rule storage behind an implementation pointer")
endif()

if(NOT rule_source MATCHES "std::shared_ptr[ \t\r\n]*<[ \t\r\n]*const[ \t\r\n]+InboundRule[ \t\r\n]*>[ \t\r\n]+rules_snapshot")
    message(FATAL_ERROR
        "rule::Manager implementation must keep detect rules behind an immutable snapshot pointer")
endif()

if(rule_header MATCHES "InboundRule[ \t\r\n]+inbound_rule" OR
   rule_source MATCHES "InboundRule[ \t\r\n]+inbound_rule_")
    message(FATAL_ERROR
        "rule::Manager must not keep a directly mutable inbound_rule_ map for hot rule updates")
endif()

if(NOT rule_source MATCHES "std::make_shared[ \t\r\n]*<[ \t\r\n]*InboundRule[ \t\r\n]*>[ \t\r\n]*\\(" OR
   NOT rule_source MATCHES "rules_snapshot[ \t\r\n]*=[ \t\r\n]*std::move\\(")
    message(FATAL_ERROR
        "rule::Manager::UpdateRule must build and replace a new rules snapshot")
endif()

if(rule_source MATCHES "inbound_rule_\\[[^\\]]+\\]" OR
   rule_source MATCHES "inbound_rule_\\.erase" OR
   rule_source MATCHES "inbound_rule_\\.find")
    message(FATAL_ERROR
        "rule::Manager hot update/read path must use the current immutable snapshot, not mutate/read a live inbound_rule_ member")
endif()
