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

using namespace acpp;
namespace http = acpp::api::v2board::http;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
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

void TestChunkedBodyAlreadyBufferedBeforeEof() {
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

void TestFragmentedChunksExtensionsAndTrailers() {
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

void TestContentLengthStillUsesPrefetchedBody() {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    });

    Check(response.status == 200, "content-length response status mismatch");
    Check(response.body == "hello", "prefetched content-length body mismatch");
}

void TestMalformedChunkTerminatorRejected() {
    auto response = ReadResponse({
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3\r\nbadXX0\r\n\r\n",
    });

    Check(response.status == -1, "malformed chunk terminator was accepted");
    Check(response.body.find("missing chunk terminator") != std::string::npos,
          "malformed chunk error lost its cause");
}

void TestMalformedContentLengthRejected() {
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

void TestOversizedBodiesRejectedBeforeRead() {
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

}  // namespace

int main() {
    TestChunkedBodyAlreadyBufferedBeforeEof();
    TestFragmentedChunksExtensionsAndTrailers();
    TestContentLengthStillUsesPrefetchedBody();
    TestMalformedChunkTerminatorRejected();
    TestMalformedContentLengthRejected();
    TestOversizedBodiesRejectedBeforeRead();
    std::cout << "v2board_http_response_test: ok\n";
    return 0;
}
