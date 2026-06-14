set(hot_path_sources
    "src/app/dispatcher/default_dispatcher.cpp"
    "src/app/proxyman/inbound/handler.cpp"
    "src/app/proxyman/outbound/handler.cpp"
)

foreach(path IN LISTS hot_path_sources)
    file(READ "${PROJECT_SOURCE_DIR}/${path}" content)
    if(content MATCHES "#include[ \t]+\"acppnode/infra/config\\.hpp\"")
        message(FATAL_ERROR
            "Hot-path implementation ${path} must include config_types.hpp instead of the full Config class header")
    endif()
endforeach()
