# Keep ISA-specific code in upstream assembly files. The dispatcher remains
# baseline code and checks CPUID/OS XSAVE support before selecting a backend.
# Never apply -march=native or /arch:AVX to the whole library/application.
option(CNODE_BLAKE3_SIMD "Enable runtime-dispatched BLAKE3 SIMD backends" ON)

set(_blake3_amd64 FALSE)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(MSVC AND CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^[Xx]64$")
        set(_blake3_amd64 TRUE)
    elseif(NOT MSVC AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
        set(_blake3_amd64 TRUE)
    endif()
endif()

if(CNODE_BLAKE3_SIMD AND _blake3_amd64 AND
   (MSVC OR CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"))
    if(MSVC)
        enable_language(ASM_MASM)
        set(_blake3_asm_suffix x86-64_windows_msvc.asm)
    else()
        enable_language(ASM)
        if(WIN32 OR CYGWIN)
            set(_blake3_asm_suffix x86-64_windows_gnu.S)
        else()
            set(_blake3_asm_suffix x86-64_unix.S)
        endif()
    endif()
    foreach(_backend sse2 sse41 avx2 avx512)
        target_sources(cnode_blake3 PRIVATE
            "${blake3_SOURCE_DIR}/c/blake3_${_backend}_${_blake3_asm_suffix}")
    endforeach()
    message(STATUS "BLAKE3: runtime SSE2/SSE4.1/AVX2/AVX512 dispatch, portable fallback")
else()
    target_compile_definitions(cnode_blake3 PRIVATE
        BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
        BLAKE3_USE_NEON=0)
    message(STATUS "BLAKE3: portable backend")
endif()

unset(_blake3_amd64)
unset(_blake3_asm_suffix)
unset(_backend)
