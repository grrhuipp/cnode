foreach(path IN ITEMS
        ".dockerignore"
        "Dockerfile"
        "Dockerfile.perf"
        "docker-compose.yml"
        "docker-compose.yaml"
        "compose.yml"
        "compose.yaml")
    if(EXISTS "${PROJECT_SOURCE_DIR}/${path}")
        message(FATAL_ERROR "Repository-level Docker artifact must not reappear: ${path}")
    endif()
endforeach()

file(READ "${PROJECT_SOURCE_DIR}/README.md" readme)
foreach(pattern IN ITEMS
        "Docker"
        "docker run"
        "docker compose"
        "Dockerfile")
    if(readme MATCHES "${pattern}")
        message(FATAL_ERROR "README must not advertise Docker deployment: ${pattern}")
    endif()
endforeach()
