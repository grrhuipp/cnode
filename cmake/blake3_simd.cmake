# Keep ISA-specific code in upstream assembly files. The dispatcher remains
# baseline code and checks CPUID/OS XSAVE support before selecting a backend.
# Never apply -march=native to the whole library/application.
option(CNODE_BLAKE3_SIMD "Enable runtime-dispatched BLAKE3 SIMD backends" ON)

if(CNODE_BLAKE3_SIMD AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND
   CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$" AND
   CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang)$")
    enable_language(ASM)
    foreach(_backend sse2 sse41 avx2 avx512)
        target_sources(cnode_blake3 PRIVATE
            "${blake3_SOURCE_DIR}/c/blake3_${_backend}_x86-64_unix.S")
    endforeach()
    message(STATUS "BLAKE3: runtime SSE2/SSE4.1/AVX2/AVX512 dispatch, portable fallback")
else()
    target_compile_definitions(cnode_blake3 PRIVATE
        BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
        BLAKE3_USE_NEON=0)
    message(STATUS "BLAKE3: portable backend")
endif()

unset(_backend)
