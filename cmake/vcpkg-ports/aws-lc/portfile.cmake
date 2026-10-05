# Build the pinned upstream sources without patches or source rewrites.
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO aws/aws-lc
    REF v${VERSION}
    SHA512 25b1e2987cd560012d18f9b81ee51374f6e876a1cd5645ce1d066f8625439ee39efdd2b08db0d33121ded50aaa5c8b004a8e4021e005a8f42f275b66bd551edc
    HEAD_REF main
)

vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_find_acquire_program(PERL)
get_filename_component(PERL_DIR "${PERL}" DIRECTORY)
vcpkg_add_to_path("${PERL_DIR}")
if(VCPKG_TARGET_IS_WINDOWS AND VCPKG_TARGET_ARCHITECTURE MATCHES "^(x86|x64)$")
    vcpkg_find_acquire_program(NASM)
    get_filename_component(NASM_DIR "${NASM}" DIRECTORY)
    vcpkg_add_to_path("${NASM_DIR}")
endif()
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}" OPTIONS
    -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DDISABLE_GO=ON
    -DENABLE_SOURCE_MODIFICATION=OFF)
vcpkg_cmake_install()
# Preserve export depth: upstream targets live one level below each config.
vcpkg_cmake_config_fixup(PACKAGE_NAME crypto/cmake
    CONFIG_PATH lib/crypto/cmake NO_PREFIX_CORRECTION)
vcpkg_cmake_config_fixup(PACKAGE_NAME ssl/cmake
    CONFIG_PATH lib/ssl/cmake NO_PREFIX_CORRECTION)
vcpkg_fixup_pkgconfig()
vcpkg_copy_pdbs()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/lib/crypto" "${CURRENT_PACKAGES_DIR}/debug/lib/ssl"
    "${CURRENT_PACKAGES_DIR}/lib/crypto" "${CURRENT_PACKAGES_DIR}/lib/ssl")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
