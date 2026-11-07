# Export the BoringSSL backend against the same patched OpenSSL::SSL target
# used by the application; do not discover a second TLS implementation.
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO ngtcp2/ngtcp2
    REF "v${VERSION}"
    SHA512 e01eba5a36b8c16998eaafad08eb9c5812f3f432755a484cd73dda51b958fea6d391860c8e5296a52a3973e9302e851fc66a50d0b759e85c39efe5f3251d6898
    PATCHES boringssl-targets.patch
)
vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DENABLE_STATIC_LIB=ON
        -DENABLE_SHARED_LIB=OFF
        -DENABLE_LIB_ONLY=ON
        -DBUILD_TESTING=OFF
        -DENABLE_BORINGSSL=ON
        -DENABLE_OPENSSL=OFF
        -DENABLE_GNUTLS=OFF
        -DENABLE_WOLFSSL=OFF
        -DENABLE_PICOTLS=OFF
        -DENABLE_JEMALLOC=OFF
        -DENABLE_WERROR=OFF
        -DENABLE_DEBUG=OFF
        -DENABLE_ASAN=OFF
        -DCMAKE_INSTALL_LIBDIR=lib
        -DCMAKE_INSTALL_DOCDIR=share/ngtcp2
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/ngtcp2)
vcpkg_fixup_pkgconfig()
file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")
