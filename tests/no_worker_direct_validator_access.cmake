file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_hpp)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

set(worker_text "${worker_hpp}\n${worker_cpp}")

set(forbidden_patterns
    "proxy/vmess/validator.hpp"
    "proxy/trojan/validator.hpp"
    "proxy/shadowsocks/validator.hpp"
    "vmess_validator_"
    "ss_validator_"
    "validator_\\.GetOnlineDevices"
    "validator_\\.Size"
    "ProtocolDeps\\{[^\n]*\n[^\n]*&vmess_validator_"
)

foreach(pattern IN LISTS forbidden_patterns)
    if(worker_text MATCHES "${pattern}")
        message(FATAL_ERROR
            "Worker must not directly access protocol validators; matched '${pattern}'")
    endif()
endforeach()
