#pragma once

namespace acpp {

// ============================================================================
// IProtocolData - 协议特定数据的类型安全基类
//
// 替代 std::any：
//   - 每个协议定义自己的 XxxProtocolData : IProtocolData
//   - 存储在 SessionContext::protocol_data (unique_ptr<IProtocolData>)
//   - 取用时用 static_cast（已知类型）或 dynamic_cast（运行时检查）
//   - 避免 std::bad_any_cast 异常
// ============================================================================
struct IProtocolData {
    virtual ~IProtocolData() noexcept = default;
};

}  // namespace acpp
