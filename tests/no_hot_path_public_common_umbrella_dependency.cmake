set(headers
    "include/acppnode/common/error.hpp"
    "include/acppnode/app/stats.hpp"
    "include/acppnode/app/udp_types.hpp"
    "include/acppnode/app/relay.hpp"
    "include/acppnode/app/relay_types.hpp"
    "include/acppnode/transport/async_stream.hpp"
    "include/acppnode/transport/link.hpp"
    "include/acppnode/transport/internet/timeout_scheduler.hpp"
    "include/acppnode/features/routing/dispatcher.hpp"
    "include/acppnode/features/outbound/outbound.hpp"
    "include/acppnode/proxy/inbound.hpp"
    "include/acppnode/proxy/outbound.hpp"
    "include/acppnode/sniff/sniffer.hpp"
    "include/acppnode/app/proxyman/inbound/udp_handler.hpp"
    "include/acppnode/app/proxyman/inbound/factory.hpp"
    "include/acppnode/app/dns/dns.hpp"
    "include/acppnode/common/target_address.hpp"
    "include/acppnode/common/session.hpp"
    "include/acppnode/common/mux/mux_relay.hpp"
    "include/acppnode/common/rule.hpp"
    "include/acppnode/proxy/trojan/validator.hpp"
    "include/acppnode/proxy/shadowsocks/validator.hpp"
    "include/acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"
    "include/acppnode/proxy/vmess/validator.hpp"
    "include/acppnode/app/proxyman/inbound/tcp_worker.hpp"
    "include/acppnode/transport/internet/proxy_protocol.hpp"
    "include/acppnode/transport/internet/dial_target.hpp"
    "include/acppnode/transport/internet/transport_dialer.hpp"
)

foreach(path IN LISTS headers)
    file(READ "${PROJECT_SOURCE_DIR}/${path}" content)
    if(content MATCHES "#include[ \t]+\"acppnode/common\\.hpp\"")
        message(FATAL_ERROR
            "Hot-path public header ${path} must not include the common.hpp umbrella; use narrow Asio/error/data boundaries")
    endif()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/proxy_protocol.hpp" proxy_protocol_header)
if(proxy_protocol_header MATCHES "ThreadLocalString")
    message(FATAL_ERROR
        "transport proxy_protocol.hpp must expose ordinary DTO data, not Worker-local string storage")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/dial_target.hpp" dial_target_header)
if(dial_target_header MATCHES "ThreadLocalVector")
    message(FATAL_ERROR
        "transport dial_target.hpp must expose ordinary candidate DTO containers, not Worker-local allocator vectors")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/stream_settings.hpp" stream_settings_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/ws_stream.hpp" ws_stream_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/http_headers.hpp" http_headers_header)
foreach(header IN ITEMS "${stream_settings_header}" "${ws_stream_header}")
    if(header MATCHES "std::unordered_map[ \t\r\n]*<[ \t\r\n]*std::string[ \t\r\n]*,[ \t\r\n]*std::string")
        message(FATAL_ERROR
            "transport public stream/ws headers must expose HttpHeaders, not raw unordered_map<string,string>")
    endif()
endforeach()

if(NOT stream_settings_header MATCHES "HttpHeaders[ \t\r\n]+headers" OR
   NOT ws_stream_header MATCHES "const[ \t\r\n]+transport::internet::HttpHeaders\\*" OR
   NOT http_headers_header MATCHES "using[ \t\r\n]+HttpHeaders[ \t\r\n]*=[ \t\r\n]*std::unordered_map[ \t\r\n]*<[ \t\r\n]*std::string[ \t\r\n]*,[ \t\r\n]*std::string")
    message(FATAL_ERROR
        "transport HTTP header maps should be owned by the named HttpHeaders DTO boundary")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/async_stream.hpp" async_stream_header)
if(async_stream_header MATCHES "#include[ \t]+\"acppnode/common/allocator\\.hpp\"")
    message(FATAL_ERROR
        "transport async_stream.hpp must not expose Worker-local allocator details; keep allocation strategy in the implementation")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/relay.hpp" relay_header)
if(relay_header MATCHES "#include[ \t]+\"acppnode/common/allocator\\.hpp\"" OR
   relay_header MATCHES "ThreadLocalAllocator")
    message(FATAL_ERROR
        "app/relay.hpp must not expose Worker-local timer allocation details")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/transport/internet/transport_dialer.hpp" transport_dialer_header)
if(transport_dialer_header MATCHES "#include[ \t]+\"acppnode/transport/internet/transport_stack\\.hpp\"")
    message(FATAL_ERROR
        "transport_dialer.hpp must not expose transport stack build internals; keep BuildOutboundTransport dependency in the implementation")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/mux/mux_relay.hpp" mux_relay_header)
if(mux_relay_header MATCHES "#include[ \t]+\"acppnode/(common/session|transport/async_stream)\\.hpp\"")
    message(FATAL_ERROR
        "mux_relay.hpp must use forward declarations for session context and AsyncStream")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/inbound.hpp" proxy_inbound_header)
if(proxy_inbound_header MATCHES "#include[ \t]+\"acppnode/(common/session|transport/async_stream)\\.hpp\"")
    message(FATAL_ERROR
        "proxy/inbound.hpp must use forward declarations for session context and AsyncStream instead of exposing concrete hot-path implementation headers")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/outbound.hpp" proxy_outbound_header)
if(proxy_outbound_header MATCHES "#include[ \t]+\"acppnode/(app/stats|app/udp_types|common/session|infra/config_types)\\.hpp\"")
    message(FATAL_ERROR
        "proxy/outbound.hpp must not expose stats, UDP session, session, or full config implementation headers; use narrow DTO headers and forward declarations")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/sniff/sniffer.hpp" sniff_header)
if(sniff_header MATCHES "#include[ \t]+\"acppnode/(common/target_address|common/allocator)\\.hpp\"")
    message(FATAL_ERROR
        "sniff/sniffer.hpp must expose ordinary sniff DTO data without target-address or Worker-local allocator dependencies")
endif()

if(sniff_header MATCHES "ThreadLocalString")
    message(FATAL_ERROR
        "SniffResult must not expose Worker-local string storage in the public sniff DTO")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/udp_handler.hpp" udp_handler_header)
if(udp_handler_header MATCHES "#include[ \t]+\"acppnode/common/allocator\\.hpp\"")
    message(FATAL_ERROR
        "proxyman inbound udp_handler.hpp must not expose Worker-local allocator details in public decode DTOs")
endif()

if(udp_handler_header MATCHES "ThreadLocalString[ \t\r\n]+user_email")
    message(FATAL_ERROR
        "UdpDecodeResult.user_email must be an ordinary DTO string, not Worker-local string storage")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/dns/dns.hpp" dns_header)
if(dns_header MATCHES "struct[ \t\r\n]+DnsResult[^{]*\\{[^}]*ThreadLocalVector[ \t\r\n]*<")
    message(FATAL_ERROR
        "DnsResult must expose ordinary address DTO containers, not Worker-local allocator vectors")
endif()

if(dns_header MATCHES "#include[ \t]+\"acppnode/common/allocator\\.hpp\"" OR
   dns_header MATCHES "ThreadLocal(Vector|String|UnorderedMap)" OR
   dns_header MATCHES "(class|struct)[ \t\r\n]+DnsCache([^A-Za-z0-9_]|$)" OR
   dns_header MATCHES "(ResolveKey|InflightResolve|ParsedResponse|BuildQueryTo|ParseResponse|inflight_resolves)")
    message(FATAL_ERROR
        "DNS service public header must expose only DNS API/DTOs; cache, inflight, parser, and Worker-local storage belong in implementation files")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/target_address.hpp" target_address_header)
if(target_address_header MATCHES "#include[ \t]+\"acppnode/common/(allocator|\\.\\.)")
    message(FATAL_ERROR
        "target_address.hpp must not include Worker-local allocator or common umbrella dependencies")
endif()

if(target_address_header MATCHES "ThreadLocalString[ \t\r\n]+host")
    message(FATAL_ERROR
        "TargetAddress.host must be an ordinary DTO string, not Worker-local string storage")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/session.hpp" session_header)
if(session_header MATCHES "#include[ \t]+\"acppnode/(common/allocator|sniff/sniffer)\\.hpp\"")
    message(FATAL_ERROR
        "common/session.hpp must not expose Worker-local allocator or sniff implementation dependencies")
endif()

if(session_header MATCHES "(ThreadLocal|memory::|ThreadLocalString|ThreadLocalVector)")
    message(FATAL_ERROR
        "session context DTOs must expose ordinary standard-library storage, not Worker-local allocator containers")
endif()

foreach(required_session_storage
        "std::string[ \t\r\n]+source_ip"
        "std::string[ \t\r\n]+user_email"
        "std::string[ \t\r\n]+protocol"
        "std::string[ \t\r\n]+sniff_domain"
        "std::vector[ \t\r\n]*<[ \t\r\n]*Outbound[ \t\r\n]*>[ \t\r\n]+outbounds")
    if(NOT session_header MATCHES "${required_session_storage}")
        message(FATAL_ERROR
            "session context should use ordinary std::string/std::vector DTO storage for per-connection metadata")
    endif()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/rule.hpp" rule_header)
if(rule_header MATCHES "#include[ \t]+\"acppnode/common/(allocator|string_hash)\\.hpp\"")
    message(FATAL_ERROR
        "rule.hpp must not expose Worker-local allocator or hash-map implementation dependencies")
endif()

if(rule_header MATCHES "ThreadLocal(Vector|UnorderedMap)" OR
   rule_header MATCHES "GetDetectResult[^(]*\\([^)]*\\)[ \t\r\n;{]*memory::ThreadLocalVector")
    message(FATAL_ERROR
        "rule::Manager public header must hide Worker-local rule storage and return ordinary detect-result DTO containers")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/trojan/validator.hpp" trojan_validator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/trojan/validator.cpp" trojan_validator_source)
if(trojan_validator_header MATCHES "#include[ \t]+\"acppnode/common/(allocator|sharded_user_stats|string_hash)\\.hpp\"" OR
   trojan_validator_header MATCHES "(ThreadLocal|UserOnlineTracker|users_by_tag_|UserMap)")
    message(FATAL_ERROR
        "Trojan validator public header must not expose Worker-local user maps or online-tracker storage")
endif()

if(NOT trojan_validator_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT trojan_validator_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "Trojan validator should hide runtime user and online-tracker storage behind an implementation pointer")
endif()

if(NOT trojan_validator_source MATCHES "struct[ \t\r\n]+Validator::Impl" OR
   NOT trojan_validator_source MATCHES "UserStore::FindTrojanUser" OR
   NOT trojan_validator_source MATCHES "UserOnlineTracker[ \t\r\n]+stats" OR
   trojan_validator_source MATCHES "ThreadLocalUnorderedMap<std::string")
    message(FATAL_ERROR
        "Trojan validator implementation should read global UserStore credentials and keep only online tracking locally")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/shadowsocks/validator.hpp" ss_validator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/shadowsocks/validator.cpp" ss_validator_source)
if(ss_validator_header MATCHES "#include[ \t]+\"acppnode/common/(allocator|sharded_user_stats|string_hash)\\.hpp\"" OR
   ss_validator_header MATCHES "(ThreadLocal|UserOnlineTracker|users_by_tag_|UserList)")
    message(FATAL_ERROR
        "Shadowsocks validator public header must not expose Worker-local user lists or online-tracker storage")
endif()

if(NOT ss_validator_header MATCHES "ShadowsocksUsersView[ \t\r\n]+FindUsersForTag" OR
   NOT ss_validator_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT ss_validator_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "Shadowsocks validator should expose an immutable UserStore view and hide online-tracker storage behind an implementation pointer")
endif()

if(NOT ss_validator_source MATCHES "struct[ \t\r\n]+Validator::Impl" OR
   NOT ss_validator_source MATCHES "UserStore::ShadowsocksUsers" OR
   NOT ss_validator_source MATCHES "UserOnlineTracker[ \t\r\n]+stats" OR
   ss_validator_source MATCHES "ThreadLocalVector<SsUserInfo>")
    message(FATAL_ERROR
        "Shadowsocks validator implementation should read global UserStore credentials and keep only online tracking locally")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/vmess/validator.hpp" vmess_validator_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/vmess/validator.cpp" vmess_validator_source)
if(vmess_validator_header MATCHES "#include[ \t]+\"acppnode/common/(allocator|sharded_user_stats|string_hash)\\.hpp\"" OR
   vmess_validator_header MATCHES "#include[ \t]+\"acppnode/infra/log\\.hpp\"" OR
   vmess_validator_header MATCHES "(ThreadLocal|UserOnlineTracker|users_by_tag_|UserMap|HotUserCache|hot_cache_|last_hot_cache_cleanup_)")
    message(FATAL_ERROR
        "VMess validator public header must not expose Worker-local user maps, hot auth cache, or online-tracker storage")
endif()

if(NOT vmess_validator_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT vmess_validator_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "VMess validator should hide runtime user, hot-cache, and online-tracker storage behind an implementation pointer")
endif()

if(NOT vmess_validator_source MATCHES "struct[ \t\r\n]+TimedUserValidator::Impl" OR
   NOT vmess_validator_source MATCHES "UserStore::VmessUsers" OR
   NOT vmess_validator_source MATCHES "std::shared_ptr[ \t\r\n]*<[ \t\r\n]*const[ \t\r\n]+proxyman::inbound::UserStore::VmessUserMap[ \t\r\n]*>[ \t\r\n]+hot_users" OR
   NOT vmess_validator_source MATCHES "HotUserCache" OR
   NOT vmess_validator_source MATCHES "UserOnlineTracker[ \t\r\n]+stats")
    message(FATAL_ERROR
        "VMess validator implementation should read global UserStore credentials and keep only hot auth cache plus online tracking locally")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/tcp_worker.hpp" tcp_worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/proxyman/inbound/tcp_worker.cpp" tcp_worker_source)
if(tcp_worker_header MATCHES "#include[ \t]+\"acppnode/common/allocator\\.hpp\"" OR
   tcp_worker_header MATCHES "(ThreadLocal|acceptors_|ThreadLocalUnorderedMap)" OR
   tcp_worker_header MATCHES "AddAcceptor" OR
   tcp_worker_header MATCHES "memory::")
    message(FATAL_ERROR
        "Proxyman inbound tcp_worker.hpp must not expose Worker-local listener map or allocator storage")
endif()

if(NOT tcp_worker_header MATCHES "CreateAcceptor")
    message(FATAL_ERROR
        "Proxyman inbound TcpWorker should own acceptor construction behind a narrow operation API")
endif()

if(NOT tcp_worker_header MATCHES "std::vector[ \t\r\n]*<[ \t\r\n]*std::string[ \t\r\n]*>[ \t\r\n]+ListenerKeys" OR
   NOT tcp_worker_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT tcp_worker_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "Proxyman inbound TcpWorker should expose ordinary listener-key DTOs and hide acceptor storage behind an implementation pointer")
endif()

if(NOT tcp_worker_source MATCHES "struct[ \t\r\n]+TcpWorker::Impl" OR
   NOT tcp_worker_source MATCHES "ThreadLocalUnorderedMap<std::string,[ \t\r\n]*tcp::acceptor")
    message(FATAL_ERROR
        "Proxyman inbound TcpWorker implementation should privately own Worker-local acceptor storage")
endif()

file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/features/outbound/outbound.hpp" outbound_feature)
if(outbound_feature MATCHES "#include[ \t]+\"acppnode/infra/config_types\\.hpp\"")
    message(FATAL_ERROR
        "features/outbound/outbound.hpp must depend on runtime_config_types.hpp, not the full config_types collection")
endif()

if(NOT outbound_feature MATCHES "#include[ \t]+\"acppnode/infra/runtime_config_types\\.hpp\"")
    message(FATAL_ERROR
        "features/outbound/outbound.hpp should include the narrow runtime config type boundary for TimeoutsConfig")
endif()
