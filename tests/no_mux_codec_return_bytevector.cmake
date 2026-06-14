file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/common/mux/mux_codec.hpp" header)
file(READ "${PROJECT_SOURCE_DIR}/src/common/mux/mux_codec.cpp" source)

if(header MATCHES "\\[\\[nodiscard\\]\\][ \t\r\n]+memory::ByteVector[ \t\r\n]+Encode")
    message(FATAL_ERROR
        "Mux codec public API must not return owned ByteVector frames; use caller-provided scratch via Encode*To")
endif()

if(header MATCHES "common\\.hpp" OR
   header MATCHES "common/allocator\\.hpp" OR
   header MATCHES "memory::ByteVector" OR
   header MATCHES "ThreadLocal")
    message(FATAL_ERROR
        "Mux codec public header must expose ordinary vector scratch APIs without common umbrella or Worker-local allocator storage")
endif()

foreach(required_signature
        "void[ \t\r\n]+EncodeKeepAliveTo\\([ \t\r\n]*std::vector<uint8_t>&[ \t\r\n]+out"
        "void[ \t\r\n]+EncodeEndTo\\([ \t\r\n]*std::vector<uint8_t>&[ \t\r\n]+out"
        "void[ \t\r\n]+EncodeKeepDataTo\\([ \t\r\n]*std::vector<uint8_t>&[ \t\r\n]+out"
        "bool[ \t\r\n]+EncodeKeepUDPTo\\([ \t\r\n]*std::vector<uint8_t>&[ \t\r\n]+out")
    if(NOT header MATCHES "${required_signature}")
        message(FATAL_ERROR
            "Mux codec public encoders must use caller-provided std::vector<uint8_t> scratch")
    endif()
endforeach()

if(source MATCHES "memory::ByteVector[ \t\r\n]+Encode(KeepAlive|End|KeepData|KeepUDP)[ \t\r\n]*\\(")
    message(FATAL_ERROR
        "Mux codec must not keep unused ByteVector-returning frame builders")
endif()
