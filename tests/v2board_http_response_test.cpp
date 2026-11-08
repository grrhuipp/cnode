#include <stdexcept>
#include <gtest/gtest.h>

#include "http_response.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace http = ::api::v2board::http;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

class ScriptedStream {
public:
    using executor_type = net::io_context::executor_type;

    ScriptedStream(net::io_context& io_context, std::vector<std::string> segments)
        : executor_(io_context.get_executor())
        , segments_(std::move(segments)) {}

    executor_type get_executor() noexcept {
        return executor_;
    }

    template <typename MutableBufferSequence, typename CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers,
                         CompletionToken&& token) {
        return net::async_initiate<
            CompletionToken,
            void(IoErrorCode, std::size_t)>(
            [this](auto&& handler, MutableBufferSequence target) mutable {
                net::post(
                    executor_,
                    [this,
                     handler = std::forward<decltype(handler)>(handler),
                     target]() mutable {
                        ++read_calls_;
                        while (segment_index_ < segments_.size() &&
                               segment_offset_ == segments_[segment_index_].size()) {
                            ++segment_index_;
                            segment_offset_ = 0;
                        }
                        if (segment_index_ >= segments_.size()) {
                            std::move(handler)(io_error::eof, 0);
                            return;
                        }

                        const auto& segment = segments_[segment_index_];
                        const auto source = net::buffer(
                            segment.data() + segment_offset_,
                            segment.size() - segment_offset_);
                        const size_t copied = net::buffer_copy(target, source);
                        segment_offset_ += copied;
                        std::move(handler)(IoErrorCode{}, copied);
                    });
            },
            token,
            buffers);
    }

    [[nodiscard]] size_t ReadCalls() const noexcept {
        return read_calls_;
    }

private:
    executor_type executor_;
    std::vector<std::string> segments_;
    size_t segment_index_ = 0;
    size_t segment_offset_ = 0;
    size_t read_calls_ = 0;
};

http::Response ReadResponse(std::vector<std::string> segments,
                            size_t* read_calls = nullptr) {
    net::io_context io_context;
    ScriptedStream stream(io_context, std::move(segments));
    auto future = net::co_spawn(
        io_context,
        http::ReadResponse(stream),
        net::use_future);
    io_context.run();
    auto response = future.get();
    if (read_calls) {
        *read_calls = stream.ReadCalls();
    }
    return response;
}

TEST(V2BoardHttpResponse, ChunkedBodyAlreadyBufferedBeforeEof) {
    size_t read_calls = 0;
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
    }, &read_calls);

    if (response.status != 200) {
        std::cerr << "prefetched response status=" << response.status
                  << " body=" << response.body
                  << " read_calls=" << read_calls << '\n';
        Fail("prefetched chunked response status mismatch");
    }
    Check(response.body == "OK", "prefetched chunked body was lost");
    Check(read_calls == 1, "chunked reader waited for EOF after terminal chunk");
}

TEST(V2BoardHttpResponse, FragmentedChunksExtensionsAndTrailers) {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: \"abc\"\r\n\r\n"
        "4;sour",
        "ce=nginx\r\nWi",
        "ki\r\n5\r\nped",
        "ia\r\n0\r\nX-Trace: yes\r\n",
        "\r\n",
    });

    Check(response.status == 200, "fragmented chunked response status mismatch");
    Check(response.body == "Wikipedia", "fragmented chunked body mismatch");
    Check(response.etag == "abc", "response ETag mismatch");
}

TEST(V2BoardHttpResponse, ContentLengthStillUsesPrefetchedBody) {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    });

    Check(response.status == 200, "content-length response status mismatch");
    Check(response.body == "hello", "prefetched content-length body mismatch");
}

TEST(V2BoardHttpResponse, MalformedChunkTerminatorRejected) {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3\r\nbadXX0\r\n\r\n",
    });

    Check(response.status == -1, "malformed chunk terminator was accepted");
    Check(response.body.find("missing chunk terminator") != std::string::npos,
          "malformed chunk error lost its cause");
}

TEST(V2BoardHttpResponse, MalformedContentLengthRejected) {
    auto trailing = ReadResponse({
        "HTTP/1.1 200 OK\r\nContent-Length: 5junk\r\n\r\nhello",
    });
    Check(trailing.status == -1,
          "Content-Length with trailing garbage was accepted");

    auto negative = ReadResponse({
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
    });
    Check(negative.status == -1,
          "negative Content-Length was accepted");

    auto conflicting = ReadResponse({
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 4\r\n\r\nhello",
    });
    Check(conflicting.status == -1,
          "conflicting Content-Length values were accepted");
}

TEST(V2BoardHttpResponse, OversizedBodiesRejectedBeforeRead) {
    auto fixed = ReadResponse({
        "HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\n\r\n",
    });
    Check(fixed.status == -1, "oversized fixed body was accepted");
    Check(fixed.body.find("body too large") != std::string::npos,
          "oversized fixed body lost its cause");

    auto chunked = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "4000001\r\n",
    });
    Check(chunked.status == -1, "oversized chunked body was accepted");
    Check(chunked.body.find("body too large") != std::string::npos,
          "oversized chunked body lost its cause");
}

TEST(V2BoardHttpResponse, OversizedHeadersRejected) {
    std::string oversized_line = "HTTP/1.1 200 OK\r\nX-Large: ";
    oversized_line.append(64 * 1024, 'x');
    oversized_line += "\r\n\r\n";
    auto line_response = ReadResponse({std::move(oversized_line)});
    Check(line_response.status == -1,
          "oversized regular header line was accepted");
    Check(line_response.body.find("line too large") != std::string::npos,
          "oversized header line lost its cause");

    std::string oversized_section = "HTTP/1.1 200 OK\r\n";
    for (int i = 0; i < 5; ++i) {
        oversized_section += "X-Part: ";
        oversized_section.append(60 * 1024, 'y');
        oversized_section += "\r\n";
    }
    oversized_section += "\r\n";
    auto section_response = ReadResponse({std::move(oversized_section)});
    Check(section_response.status == -1,
          "oversized regular header section was accepted");
    Check(section_response.body.find("headers too large") != std::string::npos,
          "oversized header section lost its cause");
}

TEST(V2BoardHttpResponse, IncompleteHeadersReturnStructuredError) {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nX-Incomplete: value",
    });
    Check(response.status == -1,
          "unterminated response headers were accepted");
    Check(response.body.find("invalid HTTP response headers") != std::string::npos,
          "unterminated response headers escaped structured error handling");
}

TEST(V2BoardHttpResponse, EtagWithControlBytesRejected) {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nETag: \"abc\nInjected: yes\"\r\nContent-Length: 2\r\n\r\nOK",
    });
    Check(response.status == -1, "ETag with control bytes was accepted");

    auto weak = ReadResponse({
        "HTTP/1.1 200 OK\r\nETag: W/\"abc\"\r\nContent-Length: 2\r\n\r\nOK",
    });
    Check(weak.status == 200 && weak.etag == "W/\"abc\"",
          "weak ETag from an intermediary was not preserved");
}

void CheckRejected(const std::string& wire,
                   std::string_view cause,
                   std::string_view message) {
    auto response = ReadResponse({wire});
    if (response.status != -1 || response.body.find(cause) == std::string::npos) {
        std::cerr << "status=" << response.status << " body=" << response.body << '\n';
        Fail(message);
    }
}

TEST(V2BoardHttpResponse, TransferCodingListParsed) {
    auto mixed_case = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: , CHUNKED ,\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
    });
    Check(mixed_case.status == 200 && mixed_case.body == "OK",
          "case-insensitive chunked coding with empty list elements was rejected");

    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
        "unsupported HTTP Transfer-Encoding",
        "undecodable coding before chunked was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
        "unsupported HTTP Transfer-Encoding",
        "coding list split across field lines was not combined");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nOK",
        "unsupported HTTP Transfer-Encoding",
        "non-final chunked coding was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
        "unsupported HTTP Transfer-Encoding",
        "repeated chunked coding was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: x-chunked\r\n\r\nOK",
        "unsupported HTTP Transfer-Encoding",
        "unknown coding containing \"chunked\" was decoded as chunked");
}

TEST(V2BoardHttpResponse, AmbiguousFramingRejected) {
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
        "both Transfer-Encoding and Content-Length",
        "Transfer-Encoding with Content-Length was accepted");
    CheckRejected(
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\n",
        "Transfer-Encoding in HTTP/1.0",
        "HTTP/1.0 response with Transfer-Encoding was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1 0\r\n0123456789abcdef\r\n0\r\n\r\n",
        "invalid chunk size",
        "chunk size with whitespace between digits was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA",
        "trailing bytes after Content-Length body",
        "Content-Length body with trailing bytes was accepted or silently truncated");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nX",
        "trailing bytes after Content-Length body",
        "zero Content-Length response with trailing byte was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2\r\nOK\r\n0\r\n\r\nTRAILING",
        "trailing bytes after chunked body",
        "chunked response with trailing bytes after terminal chunk was accepted");
    CheckRejected(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2\r\nOK\r\n0\r\nX-Trailer: 1\r\n\r\nTRAILING",
        "trailing bytes after chunked body",
        "chunked response with trailing bytes after trailer section was accepted");

    auto extension = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "2 ;name=value\r\nOK\r\n0\r\n\r\n",
    });
    Check(extension.status == 200 && extension.body == "OK",
          "chunk extension after BWS was rejected");
}

TEST(V2BoardHttpResponse, ChunkExtensionGrammarAndBoundaries) {
    using transport::internet::ParseHttpChunkSize;
    const std::string max_hex(sizeof(size_t) * 2, 'f');
    Check(ParseHttpChunkSize(max_hex) == std::numeric_limits<size_t>::max(),
          "maximum chunk size rejected");
    Check(!ParseHttpChunkSize(max_hex + "0"), "overflow chunk size accepted");
    const std::string max_line = "2;" + std::string(http::kMaxHttpLineSize - 2, 'x');
    const auto boundary = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + max_line + "\r",
        "\nOK\r\n0\r\n\r\n"});
    Check(boundary.status == 200 && boundary.body == "OK",
          "CR/LF split after maximum chunk line was rejected");
    const auto overlong = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + max_line + "x\r\nOK\r\n0\r\n\r\n"});
    Check(overlong.status == -1, "overlong chunk line was accepted");
    for (const std::string_view line : {
             "2", "02", "2;flag", "2 \t; name \t= \tvalue; next=\"\"",
             "2;name=\"a; b=\\\"quoted\\\"\\\\end\"",
             "2;name=\"\t\x80\xff\""}) {
        Check(ParseHttpChunkSize(line) == 2, "valid chunk extension grammar rejected");
        const std::string wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
            std::string(line) + "\r\nOK\r\n0;done\r\n\r\n";
        // Every possible split covers CR/LF and quoted-pair fragmentation.
        for (size_t split = wire.find("\r\n\r\n") + 4; split < wire.size(); ++split) {
            const auto response = ReadResponse({wire.substr(0, split), wire.substr(split)});
            Check(response.status == 200 && response.body == "OK",
                  "fragmented chunk extension or CRLF changed body");
        }
    }
    for (const std::string_view line : {
             "", " 2", "+2", "0x2", "2 0", "2 ", "2;", "2;=x", "2;x=",
             "2;x=a b", "2;x=\"unterminated", "2;x=\"dangling\\",
             "2;x=\"a\"junk", "2;x=\"\r\"", "2;x=\"\n\"", "2;x=\"\\\r\"",
             "2;x=\"\x7f\"", "2;x=\"\\\x7f\"", "2\r\n"}) {
        Check(!ParseHttpChunkSize(line), "malformed chunk extension grammar accepted");
        const auto response = ReadResponse({
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
            std::string(line) + "\r\nOK\r\n0\r\n\r\n"});
        Check(response.status == -1, "malformed wire chunk extension accepted");
    }
    for (const std::string_view body : {
             "2\nOK\r\n0\r\n\r\n", "2\rX\nOK\r\n0\r\n\r\n",
             "2\r\nOK\n0\r\n\r\n", "2\r\nO", "0\r\n"}) {
        const auto response = ReadResponse({
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + std::string(body)});
        Check(response.status == -1, "invalid CRLF or incomplete chunk body accepted");
    }
}

TEST(V2BoardHttpResponse, NotModifiedEndsAtHeaderSection) {
    size_t read_calls = 0;
    auto response = ReadResponse({
        "HTTP/1.1 304 Not Modified\r\nETag: \"v2\"\r\nContent-Length: 1024\r\n\r\n",
    }, &read_calls);
    Check(response.status == 304 && response.not_modified,
          "304 announcing Content-Length was not reported as not modified");
    Check(response.etag == "v2" && response.body.empty(),
          "304 response carried a body or lost its ETag");
    Check(read_calls == 1, "304 response waited for a body");
}

TEST(V2BoardHttpResponse, InterimResponsesSkipped) {
    auto response = ReadResponse({
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
        "HTTP/1.1 200 OK\r\nETag: \"final\"\r\nContent-Length: 2\r\n\r\nOK",
    });
    Check(response.status == 200 && response.body == "OK",
          "interim 1xx response was taken as the final response");
    Check(response.etag == "final", "final response ETag mismatch after 1xx");

    CheckRejected(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        "unexpected HTTP 101",
        "unsolicited protocol switch was accepted");
    Check(ReadResponse({"GARBAGE 99999 OK\r\nContent-Length: 0\r\n\r\n"}).status == -1,
          "non-HTTP status line was accepted");
    Check(ReadResponse({"HTTP/1.1 200 OK\r\nBad Header : value\r\nContent-Length: 0\r\n\r\n"}).status == -1,
          "header name with trailing whitespace was accepted");
}

}  // namespace

