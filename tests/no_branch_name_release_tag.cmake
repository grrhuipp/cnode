file(READ "${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml" ci_workflow)
file(READ "${PROJECT_SOURCE_DIR}/scripts/cnode.sh" deploy_script)

foreach(pattern IN ITEMS
        "gh release delete \"\\$\\{\\{ github\\.ref_name \\}\\}\""
        "gh release create \"\\$\\{\\{ github\\.ref_name \\}\\}\"")
    if(ci_workflow MATCHES "${pattern}")
        message(FATAL_ERROR "CI must not use branch names such as master/main as release tags: ${pattern}")
    endif()
endforeach()

if(NOT ci_workflow MATCHES "RELEASE_TAG:[^\n]*cnode-\\$\\{\\{ github\\.run_id \\}\\}-\\$\\{\\{ github\\.run_attempt \\}\\}")
    message(FATAL_ERROR "CI release tags must be unique per workflow run attempt")
endif()

if(NOT ci_workflow MATCHES "BUILD_ID:[^\n]*\\$\\{\\{ github\\.run_id \\}\\}-\\$\\{\\{ github\\.run_attempt \\}\\}")
    message(FATAL_ERROR "Build ID must include run_attempt so rerun artifacts have an unambiguous version")
endif()

if(NOT ci_workflow MATCHES "build_id:[^\n]*\\$\\{\\{ env\\.BUILD_ID \\}\\}")
    message(FATAL_ERROR "Release notes must include a parseable build_id field")
endif()

foreach(pattern IN ITEMS
        "\\.github/workflows/ci\\.yml"
        "scripts/\\*\\*/\\*\\.sh"
        "tests/\\*\\*/\\*\\.cmake")
    if(NOT ci_workflow MATCHES "${pattern}")
        message(FATAL_ERROR "CI path filters must include release/deploy guard files: ${pattern}")
    endif()
endforeach()

if(deploy_script MATCHES "RELEASE_TAG=\"\\$\\{v:-master\\}\"")
    message(FATAL_ERROR "Deployment script must not default to the branch-name release tag master")
endif()

if(NOT deploy_script MATCHES "RELEASE_TAG=\"\\$\\{v:-latest\\}\"")
    message(FATAL_ERROR "Deployment script must default to the latest GitHub release")
endif()

if(NOT deploy_script MATCHES "releases/latest")
    message(FATAL_ERROR "Deployment script must support GitHub's latest release endpoint")
endif()

string(FIND "${deploy_script}" "build_id: \\([^,[:space:]]*\\)" build_id_parse_pattern_pos)
if(build_id_parse_pattern_pos EQUAL -1)
    message(FATAL_ERROR "Deployment script must parse build_id without swallowing a trailing comma")
endif()
