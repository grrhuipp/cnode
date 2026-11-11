#include "transport/internet/http2_server.hpp"

namespace transport::internet::h2 {
net::awaitable<bool> Http2ServerSession::RouteXHttpRequest(
        uint32_t stream_id,
        bool end_stream,
        H2RequestHeaders request,
        std::shared_ptr<Http2ServerSubStreamState> sub) {
        if (const std::string_view expected_host =
                ResolveConfiguredHttpHost(http_config_->host, &http_config_->headers);
            !expected_host.empty() &&
            !AuthorityMatchesHost(request.authority, expected_host)) {
            LOG_CONN_DEBUG(conn_id_,
                "XHTTP server H2 host mismatch expected='{}' actual='{}'",
                PublicHttpTargetForLog(expected_host),
                PublicHttpTargetForLog(request.authority));
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }

        const auto meta = ParseXHttpRequestMeta(
            http_config_->path,
            request.path,
            request.method);
        if (!XHttpKindAllowed(meta.kind, *xhttp_config_))
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        switch (meta.kind) {
        case XHttpRequestMeta::Kind::StreamOne: {
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 stream-one ready stream_id={}",
                          stream_id);
            DeliverRequest(std::move(sub), nullptr, std::move(request.metadata));
            co_return true;
        }
        case XHttpRequestMeta::Kind::PacketDown: {
            auto xsession = co_await GetXHttpPacketSession(coordinator_, 
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Open);
            if (!xsession) co_return co_await ResetStream(stream_id, H2Error::Protocol);
            XHttpDownlinkClaim claim(*xsession);
            if (!claim) co_return co_await ResetStream(stream_id, H2Error::Protocol);
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 split downlink ready session={} stream_id={} mode={}",
                          meta.session_id,
                          stream_id,
                          xhttp_config_->AcceptsStreamUp() ? "stream-up" : "packet-up");
            claim.Release();
            DeliverRequest(std::move(sub), std::move(xsession), std::move(request.metadata));
            co_return true;
        }
        case XHttpRequestMeta::Kind::StreamUp: {
            auto xsession = co_await GetXHttpPacketSession(coordinator_, 
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Open);
            if (!xsession) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (!xsession->CanAttachStream()) {
                LOG_CONN_DEBUG(conn_id_,
                    "XHTTP server rejected concurrent H2 stream-up session={}",
                    meta.session_id);
                constexpr std::array<uint8_t, 1> kBadRequestStatus{
                    0x80 | kHpackStaticStatusBadRequest};
                const bool ok = co_await WriteFrameSerialized(
                    H2FrameType::HEADERS, kFlagEndHeaders | kFlagEndStream,
                    stream_id, kBadRequestStatus);
                RemoveStream(stream_id);
                co_return ok;
            }
            bool accepting = true;
            struct StreamUpGuard {
                XHttpPacketUpSession* session;
                bool& active;
                ~StreamUpGuard() {
                    if (active && session->CanAttachStream()) session->Close();
                }
            } guard{xsession.get(), accepting};
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            accepting = false;
            LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 stream-up upload ready session={} stream_id={}",
                          meta.session_id,
                          stream_id);
            sub->SetUploadBudget(xsession);
            auto upload = std::make_unique<Http2ServerSubStream>(sub);
            if (!xsession->AttachStream(std::move(upload))) {
                LOG_CONN_DEBUG(conn_id_,
                    "XHTTP server rejected concurrent H2 stream-up session={}",
                    meta.session_id);
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            auto* raw_xsession = xsession.get();
            try {
                Spawn(Http2ServerSubStreamState::JoinOwner(std::move(sub), std::move(xsession)));
            } catch (...) {
                raw_xsession->Close();
                throw;
            }
            co_return true;
        }
        case XHttpRequestMeta::Kind::PacketUp: {
            auto xsession = co_await GetXHttpPacketSession(coordinator_, 
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Upload);
            if (!xsession) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            sub->SetUploadBudget(xsession);
            auto upload = std::make_unique<Http2ServerSubStream>(std::move(sub));
            bool spawn_failed = false;
            try {
                Spawn(RunPacketUpload(std::move(upload), std::move(xsession), meta.seq));
            } catch (...) {
                spawn_failed = true;
            }
            if (spawn_failed) {
                co_return co_await ResetStream(stream_id, H2Error::Cancel);
            }
            co_return true;
        }
        case XHttpRequestMeta::Kind::Unknown:
            break;
        }
        LOG_CONN_DEBUG(conn_id_, "XHTTP server received unknown H2 request method='{}' path='{}'",
                      PublicHttpMethodForLog(request.method),
                      PublicHttpTargetForLog(request.path));
        co_return co_await ResetStream(stream_id, H2Error::Protocol);
    }
}
