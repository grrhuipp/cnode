# The registry is still at 3.5.3. Keep 3.6.1 and expose a non-overriding archive
# for unit tests; only the daemon whole-archives the overriding variant.
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO microsoft/mimalloc
    REF "v${VERSION}"
    SHA512 03090fbcfe16aff6b640ef64f8d26551f0347c9e49fbca4efc48d6874ec87c109227fa05157e21e2031d58fe9374a8af9a5e34cf67a2255806f32e39ce4ca3ed
    PATCHES static-no-override.patch
)
vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DMI_USE_CXX=ON
        -DMI_OVERRIDE=ON
        -DMI_LIBC_MUSL=ON
        -DMI_BUILD_STATIC=ON
        -DMI_BUILD_SHARED=OFF
        -DMI_BUILD_OBJECT=OFF
        -DMI_BUILD_TESTS=OFF
        -DMI_INSTALL_TOPLEVEL=ON
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF
        -DCMAKE_INSTALL_LIBDIR=lib
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/mimalloc)
vcpkg_fixup_pkgconfig()
file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
