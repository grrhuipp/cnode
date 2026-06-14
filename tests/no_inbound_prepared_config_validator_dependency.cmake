file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/prepared_config.hpp" prepared_config)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/trojan/validator.hpp" trojan_validator)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/shadowsocks/validator.hpp" shadowsocks_validator)

if(prepared_config MATCHES "proxy/(trojan|shadowsocks|vmess)/validator\\.hpp")
    message(FATAL_ERROR
        "Inbound prepared config must depend on prepared user data types, not full protocol validator headers")
endif()

if(NOT prepared_config MATCHES "proxy/trojan/user_info\\.hpp" OR
   NOT prepared_config MATCHES "proxy/shadowsocks/user_info\\.hpp" OR
   NOT prepared_config MATCHES "proxy/vmess/account\\.hpp")
    message(FATAL_ERROR
        "Inbound prepared config must include narrow protocol user data headers for UserSet")
endif()

if(trojan_validator MATCHES "struct[ \t\r\n]+TrojanUserInfo" OR
   shadowsocks_validator MATCHES "struct[ \t\r\n]+SsUserInfo")
    message(FATAL_ERROR
        "Protocol user data structs must live outside validator headers")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/trojan/user_info.hpp" OR
   NOT EXISTS "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/shadowsocks/user_info.hpp")
    message(FATAL_ERROR
        "Protocol user_info.hpp headers must exist as narrow prepared user data boundaries")
endif()
