file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp" outbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp" inbound_source)

foreach(pattern IN ITEMS
        "kMaxLogicalQueuedPayloadBytes[ \t\r\n]*=[ \t\r\n]*acpp::buf::Buffer::kSize[ \t\r\n]*\\*[ \t\r\n]*4"
        "queued_bytes_[ \t\r\n]*\\+[ \t\r\n]*bytes[ \t\r\n]*>[ \t\r\n]*kMaxLogicalQueuedPayloadBytes"
        "Fail\\(ErrorCode::RESOURCE_EXHAUSTED\\)"
        "queued_bytes_[ \t\r\n]*-=[ \t\r\n]*std::min\\(queued_bytes_,[ \t\r\n]*buf::TotalLen\\(mb\\)\\)"
        "size_t[ \t\r\n]+queued_bytes_[ \t\r\n]*=[ \t\r\n]*0"
        "queued_bytes_[ \t\r\n]*=[ \t\r\n]*0")
    if(NOT outbound_source MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS outbound logical streams must keep bounded queued payload bytes: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
        "kMaxSubStreamQueuedPayloadBytes[ \t\r\n]*=[ \t\r\n]*buf::Buffer::kSize[ \t\r\n]*\\*[ \t\r\n]*4"
        "queued_bytes_[ \t\r\n]*\\+[ \t\r\n]*bytes[ \t\r\n]*>[ \t\r\n]*kMaxSubStreamQueuedPayloadBytes"
        "Cancel\\(\\)"
        "queued_bytes_[ \t\r\n]*-=[ \t\r\n]*std::min\\(queued_bytes_,[ \t\r\n]*buf::TotalLen\\(mb\\)\\)"
        "size_t[ \t\r\n]+queued_bytes_[ \t\r\n]*=[ \t\r\n]*0"
        "queued_bytes_[ \t\r\n]*=[ \t\r\n]*0")
    if(NOT inbound_source MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS inbound substreams must keep bounded queued payload bytes: ${pattern}")
    endif()
endforeach()
