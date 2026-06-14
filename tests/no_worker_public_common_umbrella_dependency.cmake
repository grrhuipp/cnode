file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common.hpp" common_header)

if(worker_header MATCHES "acppnode/common\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the common.hpp umbrella; use narrow runtime/Asio boundaries instead")
endif()

if(NOT worker_header MATCHES "acppnode/common/asio_types\\.hpp")
    message(FATAL_ERROR
        "worker.hpp should include the narrow Asio type boundary for net/tcp public signatures")
endif()

if(NOT common_header MATCHES "acppnode/common/asio_types\\.hpp")
    message(FATAL_ERROR
        "common.hpp should reuse the narrow Asio type boundary instead of owning net/tcp aliases directly")
endif()
