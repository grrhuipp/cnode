file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_setup.hpp" bootstrap_setup_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_panels.hpp" bootstrap_panels_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_inbounds.hpp" bootstrap_inbounds_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_runtime.hpp" bootstrap_runtime_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_cli.hpp" bootstrap_cli_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap.hpp" bootstrap_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_monitor.hpp" bootstrap_monitor_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_shutdown.hpp" bootstrap_shutdown_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_setup.cpp" bootstrap_setup_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_panels.cpp" bootstrap_panels_source)

foreach(header_name
        bootstrap_header
        bootstrap_setup_header
        bootstrap_panels_header
        bootstrap_inbounds_header
        bootstrap_runtime_header
        bootstrap_cli_header
        bootstrap_monitor_header
        bootstrap_shutdown_header)
    if(${header_name} MATCHES "#include[ \t]+\"acppnode/common\\.hpp\"")
        message(FATAL_ERROR
            "bootstrap public headers must not include the common.hpp umbrella; use narrow Asio and explicit forward declarations")
    endif()

    if(${header_name} MATCHES "#include[ \t]+\"acppnode/infra/config\\.hpp\"" OR
       ${header_name} MATCHES "#include[ \t]+\"acppnode/app/dns/dns\\.hpp\"")
        message(FATAL_ERROR
            "bootstrap public headers must not include full Config or DNS service implementations")
    endif()
endforeach()

if(NOT bootstrap_setup_header MATCHES "#include[ \t]+\"acppnode/common/asio_types\\.hpp\"" OR
   NOT bootstrap_panels_header MATCHES "#include[ \t]+\"acppnode/common/asio_types\\.hpp\"" OR
   NOT bootstrap_runtime_header MATCHES "#include[ \t]+\"acppnode/common/asio_types\\.hpp\"")
    message(FATAL_ERROR
        "bootstrap public headers that expose Asio types should depend on the narrow Asio type boundary")
endif()

if(NOT bootstrap_setup_source MATCHES "#include[ \t]+\"acppnode/infra/config\\.hpp\"" OR
   NOT bootstrap_setup_source MATCHES "#include[ \t]+\"acppnode/app/dns/dns\\.hpp\"")
    message(FATAL_ERROR
        "bootstrap_setup.cpp should include full Config and DNS implementation headers where they are used")
endif()

if(NOT bootstrap_panels_source MATCHES "#include[ \t]+\"acppnode/infra/config\\.hpp\"" OR
   NOT bootstrap_panels_source MATCHES "#include[ \t]+\"acppnode/app/bootstrap_panels\\.hpp\"")
    message(FATAL_ERROR
        "bootstrap_panels.cpp should keep full Config usage in the cold-path implementation")
endif()
