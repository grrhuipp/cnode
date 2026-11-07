# One TLS implementation for REALITY, QUIC and all application crypto.
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO google/boringssl
    REF "${VERSION}"
    SHA512 b1f9cc7be4e1b4e3017edcf0c810f042e84af1e6a87e418b02fe9bc3dbbf78406a201f1686e65dc76119df382c871818c54ea36656c028c72c61da2ff421c358
    PATCHES reality.patch shake128.patch
)
vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_SHARED_LIBS=OFF
        -DBUILD_TESTING=OFF
        -DCMAKE_INSTALL_LIBDIR=lib
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME OpenSSL CONFIG_PATH lib/cmake/OpenSSL)
vcpkg_copy_tools(TOOL_NAMES bssl AUTO_CLEAN)
file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
