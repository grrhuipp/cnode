file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/geo/geodata.hpp" geodata_header)
file(READ "${PROJECT_SOURCE_DIR}/src/geo/geodata.cpp" geodata_cpp)

if(worker_header MATCHES "geo/geodata\\.hpp")
    message(FATAL_ERROR
        "worker.hpp must not include the full GeoData implementation header; use a GeoManager forward declaration")
endif()

if(NOT worker_header MATCHES "namespace geo[ \t\r\n]*\\{[ \t\r\n]*class GeoManager;")
    message(FATAL_ERROR
        "worker.hpp must forward declare geo::GeoManager for pointer-only runtime wiring")
endif()

foreach(forbidden_header
        "common\\.hpp"
        "common/string_hash\\.hpp"
        "<unordered_map>"
        "<unordered_set>"
        "<shared_mutex>")
    if(geodata_header MATCHES "${forbidden_header}")
        message(FATAL_ERROR
            "geodata.hpp must not expose Geo loader/index storage dependencies")
    endif()
endforeach()

foreach(forbidden_storage
        "GeoIPLoader"
        "GeoSiteLoader"
        "GeoIPData"
        "GeoSiteData"
        "IPv4RadixTrie"
        "IPv6RadixTrie"
        "SuffixTrie"
        "tag_index_"
        "loaded_"
        "geoip_loader_"
        "geosite_loader_"
        "shared_mutex"
        "TransparentStringHash")
    if(geodata_header MATCHES "${forbidden_storage}")
        message(FATAL_ERROR
            "geodata.hpp must keep Geo indexes, loaders, tries, and hash storage private")
    endif()
endforeach()

if(NOT geodata_header MATCHES "struct[ \t\r\n]+Impl;" OR
   NOT geodata_header MATCHES "std::unique_ptr[ \t\r\n]*<[ \t\r\n]*Impl[ \t\r\n]*>[ \t\r\n]+impl_")
    message(FATAL_ERROR
        "GeoManager should hide Geo loader runtime storage behind an implementation pointer")
endif()

if(NOT geodata_cpp MATCHES "class[ \t\r\n]+GeoIPLoader" OR
   NOT geodata_cpp MATCHES "class[ \t\r\n]+GeoSiteLoader" OR
   NOT geodata_cpp MATCHES "struct[ \t\r\n]+GeoManager::Impl")
    message(FATAL_ERROR
        "Geo loader and index storage should live in geodata.cpp private implementation")
endif()
