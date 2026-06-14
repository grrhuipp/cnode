file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/bootstrap_setup.hpp" bootstrap_setup_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/bootstrap_setup.cpp" bootstrap_setup_cpp)

if(bootstrap_setup_header MATCHES "app/dns/dns\\.hpp")
    message(FATAL_ERROR
        "bootstrap_setup.hpp must not include the full DNS service header; keep DNS service creation/destruction in the cold-path implementation")
endif()

if(NOT bootstrap_setup_header MATCHES "~BootstrapEnvironment[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "BootstrapEnvironment must declare an out-of-line destructor so unique_ptr<DNS> can stay behind a forward declaration")
endif()

if(NOT bootstrap_setup_cpp MATCHES "app/dns/dns\\.hpp")
    message(FATAL_ERROR
        "bootstrap_setup.cpp must include the DNS service header where the panel DNS service is constructed and destroyed")
endif()
