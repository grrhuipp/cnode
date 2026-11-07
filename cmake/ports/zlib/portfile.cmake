# zlib 1.4 is newer than the pinned registry's 1.3.2 port.
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO madler/zlib
    REF "v${VERSION}"
    SHA512 67f3ce120210a69aa05cece6f76d5f45b50d947c095169f0d699732d0182d7d04aec1af56a3fc6bbcc2af91a57e099cd73980b17f7d96ad90aeabbeaafbf1cbc
)
vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DZLIB_BUILD_TESTING=OFF
        -DZLIB_BUILD_SHARED=OFF
        -DZLIB_BUILD_STATIC=ON
        -DCMAKE_INSTALL_LIBDIR=lib
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/zlib)
vcpkg_fixup_pkgconfig()
file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
    "${CURRENT_PACKAGES_DIR}/share/man"
    "${CURRENT_PACKAGES_DIR}/share/doc")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
