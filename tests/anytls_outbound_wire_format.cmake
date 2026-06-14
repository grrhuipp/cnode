file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/anytls_codec.hpp" codec_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/anytls_codec.cpp" codec_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/proxy/anytls/outbound/anytls_outbound.hpp" outbound_header)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/outbound/anytls_outbound.cpp" outbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/inbound/anytls_inbound.cpp" inbound_source)
file(READ "${PROJECT_SOURCE_DIR}/src/proxy/anytls/validator.cpp" validator_source)
file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/userbuilder.cpp" user_builder_source)
file(READ "${PROJECT_SOURCE_DIR}/src/infra/config.cpp" config_source)
file(READ "${PROJECT_SOURCE_DIR}/src/app/static_inbound_runtime.cpp" static_runtime_source)
file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/proxyman/inbound/prepared_config.hpp" prepared_config_header)

foreach(pattern IN ITEMS
    "kCmdWaste[ \t\r\n]*=[ \t\r\n]*0"
    "kCmdSYN[ \t\r\n]*=[ \t\r\n]*1"
    "kCmdPSH[ \t\r\n]*=[ \t\r\n]*2"
    "kCmdFIN[ \t\r\n]*=[ \t\r\n]*3"
    "kCmdSettings[ \t\r\n]*=[ \t\r\n]*4"
    "kCmdAlert[ \t\r\n]*=[ \t\r\n]*5"
    "kCmdUpdatePaddingScheme[ \t\r\n]*=[ \t\r\n]*6"
    "kCmdSYNACK[ \t\r\n]*=[ \t\r\n]*7"
    "kCmdHeartRequest[ \t\r\n]*=[ \t\r\n]*8"
    "kCmdHeartResponse[ \t\r\n]*=[ \t\r\n]*9"
    "kCmdServerSettings[ \t\r\n]*=[ \t\r\n]*10"
    "kFrameHeaderSize[ \t\r\n]*=[ \t\r\n]*7"
    "kMaxFramePayload[ \t\r\n]*=[ \t\r\n]*0xffff"
    "kUotMagicAddress[ \t\r\n]*=[ \t\r\n]*\"sp\\.v2\\.udp-over-tcp\\.arpa\""
    "kDefaultAuthPaddingSize[ \t\r\n]*=[ \t\r\n]*30")
    if(NOT codec_header MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS codec must keep Xray-compatible frame/auth constants: ${pattern}")
    endif()
endforeach()

foreach(pattern IN ITEMS
    "EVP_md5"
    "DefaultPaddingScheme"
    "stop=8"
    "ParsePaddingScheme"
    "WriteU32BE\\(header[ \t\r\n]*\\+[ \t\r\n]*1"
    "WriteU16BE\\(header[ \t\r\n]*\\+[ \t\r\n]*5"
    "EncodeSocksAddress"
    "EncodeUotRequest"
    "DecodeUotRequest"
    "IsUotMagicAddress"
    "0x03"
    "0x01"
    "0x04")
    if(NOT codec_source MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS codec must encode sha256 auth, 7-byte frame headers, and SOCKS addresses: ${pattern}")
    endif()
endforeach()

if(NOT validator_source MATCHES "EVP_sha256")
    message(FATAL_ERROR "AnyTLS validator/user boundary must use sha256(password) hashes")
endif()

if(outbound_source MATCHES "wire format is not implemented" OR
   outbound_source MATCHES "NOT_SUPPORTED")
    message(FATAL_ERROR "AnyTLS outbound must not remain a NOT_SUPPORTED wire-format placeholder")
endif()

foreach(pattern IN ITEMS
    "IsTls\\(\\)"
    "PaddingScheme[ \t\r\n]+padding_scheme[ \t\r\n]*=[ \t\r\n]*DefaultPaddingScheme\\(\\)"
    "const[ \t\r\n]+auto[ \t\r\n]+default_scheme[ \t\r\n]*=[ \t\r\n]*DefaultPaddingScheme\\(\\)"
    "AuthPaddingSize\\(default_scheme\\)"
    "PasswordHash\\(settings_\\.password\\)"
    "DefaultClientSettings\\(\\)"
    "BuildFrameBytes\\([^\\n]*kCmdSettings"
    "BuildFrameBytes\\([^\\n]*kCmdSYN"
    "BuildFrameBytes\\([^\\n]*kCmdPSH"
    "WritePacketWithPadding"
    "WriteMultiBufferAsFramesWithPadding"
    "WriteFrame(Serialized)?\\([^\\n]*kCmdFIN"
    "ReadFrameHeader"
    "kCmdSYNACK"
    "kCmdAlert"
    "kCmdUpdatePaddingScheme"
    "ParsePaddingScheme"
    "ClientSession"
    "LogicalStream"
    "ReadLoop"
    "RegisterLogicalStream"
    "UnregisterLogicalStream"
    "WaitSynAck"
    "AckSyn"
    "peer_version"
    "sid[ \t\r\n]*>=[ \t\r\n]*2[ \t\r\n]*&&[ \t\r\n]*session->peer_version[ \t\r\n]*>=[ \t\r\n]*2"
    "WriteFrameSerialized"
    "WriteOpenPacket"
    "WritePayloadFrames"
    "WriteUdpPacket"
    "write_busy"
    "streams_mu"
    "logical_streams"
    "active_streams"
    "next_sid"
    "settings_sent"
    "sessions_"
    "idle_sessions_"
    "in_idle_pool"
    "settings\\.if_contains\\(\"address\"\\)"
    "settings\\.if_contains\\(\"port\"\\)"
    "settings\\.if_contains\\(\"password\"\\)"
    "idleSessionCheckInterval"
    "idleSessionTimeout"
    "minIdleSession"
    "min_idle_sessions_"
    "PruneSessionsLocked"
    "idle_sessions_\\.pop_back\\(\\)"
    "idle_sessions_\\.push_back\\(session\\)"
    "idle_since"
    "packet_index"
    "ctx\\.content\\.network[ \t\r\n]*==[ \t\r\n]*Network::UDP"
    "TargetAddress\\(kUotMagicAddress,[ \t\r\n]*0\\)"
    "EncodeUotRequest\\(original_target,[ \t\r\n]*true\\)"
    "buffer->SetUDP\\(original_target\\)")
    if(NOT outbound_source MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS outbound must perform standard auth/settings/stream frame handling: ${pattern}")
    endif()
endforeach()

if(NOT outbound_header MATCHES "std::vector<std::shared_ptr<ClientSession>>[ \t\r\n]+sessions_" OR
   NOT outbound_header MATCHES "std::vector<std::shared_ptr<ClientSession>>[ \t\r\n]+idle_sessions_")
    message(FATAL_ERROR "AnyTLS outbound must keep Xray-core style sessions map + idleSessions pool")
endif()

if(inbound_source MATCHES "wire format is not implemented" OR
   inbound_source MATCHES "PROTOCOL_UNSUPPORTED")
    message(FATAL_ERROR "AnyTLS inbound must not remain a PROTOCOL_UNSUPPORTED wire-format placeholder")
endif()

foreach(pattern IN ITEMS
    "ReadAuth"
    "Validate\\(ctx\\.inbound\\.tag,[ \t\r\n]*auth_hash\\)"
    "kCmdSettings"
    "kCmdSYN"
    "kCmdPSH"
    "kCmdSYNACK"
    "ParseSocksAddress"
    "IsUotMagicAddress"
    "DecodeUotRequest"
    "ctx\\.content\\.network[ \t\r\n]*=[ \t\r\n]*network"
    "AnyTLSDemuxSession"
    "AnyTLSSubStream"
    "StreamState"
    "PendingTarget"
    "PendingUotRequest"
    "Started"
    "stream_states_"
    "GetOrCreateStream"
    "net::co_spawn"
    "WriteFrameSerialized"
    "WriteMultiBufferSerialized"
    "CopySessionContext"
    "AnyTLSUotReader"
    "AnyTLSUotWriter"
    "AnyTLSUotSubReader"
    "ParseSettingsPaddingMd5"
    "padding_scheme_raw_"
    "padding_scheme_md5_"
    "kCmdUpdatePaddingScheme"
    "transport::Link\\{&reader,[ \t\r\n]*sub\\.get\\(\\)\\}"
    "anytls_validator->ApplyUsers"
    "anytls_validator->AddUsers"
    "anytls_validator->RemoveUsers"
    "anytls_validator->ClearUsers")
    if(NOT inbound_source MATCHES "${pattern}")
        message(FATAL_ERROR "AnyTLS inbound must authenticate users and hand a frame stream to dispatcher: ${pattern}")
    endif()
endforeach()

if(user_builder_source MATCHES "src/proxy/anytls" OR
   user_builder_source MATCHES "\\.\\./\\.\\./proxy/anytls/anytls_codec")
    message(FATAL_ERROR "Controller user builder must not include AnyTLS private codec implementation")
endif()

if(NOT user_builder_source MATCHES "result\\.anytls_users")
    message(FATAL_ERROR "Controller user builder must produce AnyTLS users for panel sync")
endif()

foreach(pattern IN ITEMS
    "paddingScheme"
    "padding_scheme"
    "StaticUserArrayKeyForProtocol"
    "constants::protocol::kAnyTLS"
    "return \"users\"")
    if(NOT config_source MATCHES "${pattern}")
        message(FATAL_ERROR "Static inbound config must parse AnyTLS paddingScheme: ${pattern}")
    endif()
endforeach()

if(outbound_source MATCHES "settings\\.if_contains\\(\"servers\"\\)")
    message(FATAL_ERROR "AnyTLS outbound settings must align xray-core top-level address/port/password, not servers[0]")
endif()

if(NOT config_source MATCHES "protocol[ \t\r\n]*==[ \t\r\n]*constants::protocol::kShadowsocks" OR
   NOT config_source MATCHES "settings\\.if_contains\\(\"password\"\\)")
    message(FATAL_ERROR "Shadowsocks inbound settings must accept xray-core top-level password")
endif()

if(NOT prepared_config_header MATCHES "anytls_padding_scheme")
    message(FATAL_ERROR "Prepared inbound BuildRequest must carry AnyTLS padding scheme on the cold path")
endif()

if(NOT static_runtime_source MATCHES "anytls_padding_scheme[ \t\r\n]*=[ \t\r\n]*source\\.static_users\\.padding_scheme")
    message(FATAL_ERROR "Static inbound runtime must pass AnyTLS padding scheme into handler BuildRequest")
endif()
