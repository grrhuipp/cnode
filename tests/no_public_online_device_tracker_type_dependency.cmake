file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/manager.hpp" manager_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/vmess/validator.hpp" vmess_validator_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/trojan/validator.hpp" trojan_validator_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/shadowsocks/validator.hpp" ss_validator_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/online_device.hpp" online_device_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/sharded_user_stats.hpp" tracker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/common/sharded_user_stats.cpp" tracker_source)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_source)

foreach(public_header
        "${worker_header}"
        "${manager_header}"
        "${vmess_validator_header}"
        "${trojan_validator_header}"
        "${ss_validator_header}")
    if(public_header MATCHES "UserOnlineTracker::OnlineDevice")
        message(FATAL_ERROR
            "public online-device APIs must expose the standalone OnlineDevice type, not UserOnlineTracker internals")
    endif()
endforeach()

foreach(public_header "${worker_header}" "${manager_header}")
    if(public_header MATCHES "common/online_device\\.hpp")
        message(FATAL_ERROR
            "Worker/proxyman inbound public headers must forward declare OnlineDevice instead of including its DTO definition")
    endif()
endforeach()

if(NOT online_device_header MATCHES "struct[ \t\r\n]+OnlineDevice")
    message(FATAL_ERROR
        "OnlineDevice must be a standalone named DTO struct")
endif()

if(online_device_header MATCHES "using[ \t\r\n]+OnlineDevice[ \t\r\n]*=[ \t\r\n]*std::pair")
    message(FATAL_ERROR
        "OnlineDevice must not be a std::pair alias; online reporting fields need named DTO ownership")
endif()

foreach(required_field "int64_t[ \t\r\n]+user_id" "std::string[ \t\r\n]+ip")
    if(NOT online_device_header MATCHES "${required_field}")
        message(FATAL_ERROR
            "OnlineDevice DTO must expose named user_id and ip fields")
    endif()
endforeach()

if(manager_header MATCHES "common/sharded_user_stats\\.hpp")
    message(FATAL_ERROR
        "proxyman inbound manager public header must not include sharded_user_stats just to expose online device results")
endif()

if(NOT tracker_header MATCHES "using[ \t\r\n]+OnlineDevice[ \t\r\n]*=[ \t\r\n]*::acpp::OnlineDevice")
    message(FATAL_ERROR
        "UserOnlineTracker must reuse the standalone OnlineDevice DTO")
endif()

foreach(forbidden
        "common/allocator\\.hpp"
        "common/string_hash\\.hpp"
        "ThreadLocal"
        "memory::"
        "connections_"
        "devices_"
        "UserConnectionMap"
        "TagConnectionMap"
        "DeviceIpMap"
        "UserDeviceMap"
        "TagDeviceMap"
        "TransparentStringHash")
    if(tracker_header MATCHES "${forbidden}")
        message(FATAL_ERROR
            "UserOnlineTracker public header must not expose worker-local tracker storage or allocator/hash dependencies")
    endif()
endforeach()

if(NOT tracker_header MATCHES "struct[ \t\r\n]+Impl" OR
   NOT tracker_header MATCHES "std::unique_ptr<Impl>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "UserOnlineTracker public header must hide tracker state behind a private Impl")
endif()

foreach(required_source_fragment
        "struct[ \t\r\n]+UserOnlineTracker::Impl"
        "ThreadLocalUnorderedMap"
        "TagConnectionMap"
        "TagDeviceMap"
        "connections"
        "devices")
    if(NOT tracker_source MATCHES "${required_source_fragment}")
        message(FATAL_ERROR
            "UserOnlineTracker private implementation must own the sharded tracker maps")
    endif()
endforeach()

if(controller_source MATCHES "UserOnlineTracker::OnlineDevice")
    message(FATAL_ERROR
        "controller online collection must consume the standalone OnlineDevice type")
endif()
