#pragma once

#include "common/allocator.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"

#include <tl/expected.hpp>

#include <memory>
#include <optional>

// 传输层构建结果：成功时为最终传输流；入站把请求交给 InboundTransportStreamHandler
// 后返回空流。单独成头，供各层握手实现使用而不引入整个 transport_stack.hpp。
namespace transport::internet {

using TransportBuildResult = tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>;

// 入站传输握手期间从请求中提取、随逻辑流交给入站处理的元数据。
struct InboundTransportMetadata {
    memory::String real_ip;
    // 传输层已识别的原生 UDP 会话的首个目标；有值即该逻辑流是 UDP 会话（Network::UDP）。
    std::optional<common::TargetAddress> udp_session_target;
};

}  // namespace transport::internet
