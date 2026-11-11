#pragma once

#include <openssl/mem.h>

#include <memory>
#include <tuple>
#include <type_traits>

// 有 data()/size() 的对象（std::array、std::span、std::string、ByteVector 等）
// 按析构时的 data()/size() 擦除所指字节；其余对象（C 数组、POD 聚合）必须可平凡复制，按整个对象擦除。
// 用法：ScopedCleanse cleanse{salt, subkey};
namespace common {

template <typename... Secrets>
class ScopedCleanse {
public:
    explicit ScopedCleanse(Secrets&... secrets) noexcept : secrets_(secrets...) {}

    ScopedCleanse(const ScopedCleanse&) = delete;
    ScopedCleanse& operator=(const ScopedCleanse&) = delete;

    ~ScopedCleanse() {
        std::apply([](auto&... secret) { (Cleanse(secret), ...); }, secrets_);
    }

private:
    template <typename T>
    static void Cleanse(T& secret) noexcept {
        if constexpr (requires { secret.data(); secret.size(); }) {
            OPENSSL_cleanse(secret.data(), secret.size() * sizeof(*secret.data()));
        } else {
            static_assert(std::is_trivially_copyable_v<T>,
                          "ScopedCleanse 只接受连续容器/视图或可平凡复制对象");
            OPENSSL_cleanse(std::addressof(secret), sizeof(T));
        }
    }

    std::tuple<Secrets&...> secrets_;
};

template <typename... Secrets>
ScopedCleanse(Secrets&...) -> ScopedCleanse<Secrets...>;

}  // namespace common
