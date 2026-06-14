file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker_stats.hpp" worker_stats_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/udp_session.hpp" udp_session_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/dns/dns.hpp" dns_header)

function(require_no_dns_service_header header_name header_content)
    if(header_content MATCHES "app/dns/dns\\.hpp")
        message(FATAL_ERROR
            "${header_name} must not include the full DNS service header; use forward declarations and narrow DNS data headers")
    endif()
endfunction()

require_no_dns_service_header("worker.hpp" "${worker_header}")
require_no_dns_service_header("udp_session.hpp" "${udp_session_header}")

if(worker_header MATCHES "app/dns/stats\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include DNS stats directly; Worker runtime stats DTOs belong in worker_stats.hpp")
endif()

if(NOT worker_stats_header MATCHES "app/dns/stats\\.hpp")
    message(FATAL_ERROR
        "worker_stats.hpp must include the narrow DNS stats boundary for WorkerRuntimeStatsSnapshot")
endif()

if(worker_header MATCHES "app::dns::DNS[ \t\r\n]+dns_service_")
    message(FATAL_ERROR
        "Worker public header must not require complete DNS service type as an inline member")
endif()

if(NOT dns_header MATCHES "app/dns/stats\\.hpp")
    message(FATAL_ERROR
        "DNS service header must include the narrow DNS stats boundary")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/app/dns/stats.hpp")
    message(FATAL_ERROR
        "app/dns/stats.hpp must exist as the narrow DNS cache stats boundary")
endif()
