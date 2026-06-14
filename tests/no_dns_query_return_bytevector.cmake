set(files
    "${PROJECT_SOURCE_DIR}/include/acppnode/app/dns/dns.hpp"
    "${PROJECT_SOURCE_DIR}/src/app/dns/dns.cpp"
)

foreach(path IN LISTS files)
    file(READ "${path}" content)
    if(content MATCHES "memory::ByteVector[ \t\r\n]+(DNS::)?BuildQuery[ \t\r\n]*\\(")
        message(FATAL_ERROR
            "DNS query builder must not return owned ByteVector packets; use caller-provided scratch storage")
    endif()
endforeach()
