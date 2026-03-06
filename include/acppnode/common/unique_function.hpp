#pragma once

#include <memory>
#include <type_traits>
#include <utility>

namespace acpp {

// ============================================================================
// unique_function - C++20 move-only function wrapper
//
// 用于存储返回 cobalt::task<T> 的 callable（task 不可拷贝，
// 不能用 std::function）。
// ============================================================================
template<typename Sig> class unique_function;
template<typename R, typename... Args>
class unique_function<R(Args...)> {
    struct base {
        virtual ~base() noexcept = default;
        virtual R call(Args... args) = 0;
    };
    template<typename F>
    struct model : base {
        mutable F f;
        template<typename U>
        explicit model(U&& u) : f(std::forward<U>(u)) {}
        R call(Args... args) override {
            return f(std::move(args)...);
        }
    };
    std::unique_ptr<base> p_;
public:
    unique_function() = default;
    unique_function(std::nullptr_t) noexcept {}  // 允许 nullptr 构造
    template<typename F>
        requires (!std::is_same_v<std::decay_t<F>, unique_function>
                  && !std::is_same_v<std::decay_t<F>, std::nullptr_t>)
    unique_function(F&& f)
        : p_(std::make_unique<model<std::decay_t<F>>>(std::forward<F>(f))) {}
    R operator()(Args... args) {
        return p_->call(std::move(args)...);
    }
    explicit operator bool() const noexcept { return p_ != nullptr; }
};

}  // namespace acpp
