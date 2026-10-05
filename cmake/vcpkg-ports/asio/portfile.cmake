# Build the pinned upstream sources without patches or source rewrites.
set(VCPKG_BUILD_TYPE release)
string(REPLACE "." "-" ref "asio-${VERSION}")
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO chriskohlhoff/asio
    REF "${ref}"
    SHA512 9374ff97bd4af7b5b41754970b2bcb468f450fee46a80c9c3344f732c64091f2ac5a73ebf4ac1831c623793c08a3c109ae90b601273c40d062bfd4f026f1d94d
    HEAD_REF master
)

file(INSTALL "${SOURCE_PATH}/asio/include/asio" "${SOURCE_PATH}/asio/include/asio.hpp"
    DESTINATION "${CURRENT_PACKAGES_DIR}/include")
file(INSTALL "${CURRENT_PORT_DIR}/asio-config.cmake"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/asio")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/asio/LICENSE_1_0.txt")
