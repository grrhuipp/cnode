#pragma once

#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "transport/link.hpp"

#include <exception>
#include <new>

namespace transport {

// 异常 → ErrorCode 的唯一分类入口。LinkError 保留跨读写边界携带的应用错误码，
// 系统 I/O 错误经 MapAsioError 映射（operation_aborted → CANCELLED），分配失败归为
// RESOURCE_EXHAUSTED；其余异常由调用方按所处阶段给出 unknown。
// 超时、取消等阶段语义由调用方在外层叠加，本函数只做类型分类。
// 前置条件：failure 非空。
[[nodiscard]] inline ErrorCode ClassifyFailure(std::exception_ptr failure,
                                               ErrorCode unknown) noexcept {
    try {
        std::rethrow_exception(failure);
    } catch (const LinkError& error) {
        return error.code();
    } catch (const IoSystemError& error) {
        return MapAsioError(error.code());
    } catch (const std::bad_alloc&) {
        return ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        return unknown;
    }
}

}  // namespace transport
