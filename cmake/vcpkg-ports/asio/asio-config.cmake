include(CMakeFindDependencyMacro)
find_dependency(Threads)
if(NOT TARGET asio::asio)
    get_filename_component(_asio_prefix "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    add_library(asio::asio INTERFACE IMPORTED)
    set_target_properties(asio::asio PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_asio_prefix}/include"
        INTERFACE_COMPILE_DEFINITIONS ASIO_STANDALONE
        INTERFACE_LINK_LIBRARIES Threads::Threads)
    if(WIN32)
        target_link_libraries(asio::asio INTERFACE ws2_32 mswsock)
    endif()
    unset(_asio_prefix)
endif()
