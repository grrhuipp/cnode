#pragma once

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>
namespace json {

enum class KeyComparison {
    CaseSensitive,
    AsciiCaseInsensitive,
};

class value;
class object;
class array;

struct object_deleter {
    void operator()(object* ptr) const noexcept;
};

struct array_deleter {
    void operator()(array* ptr) const noexcept;
};

class parse_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class value {
public:
    using object_ptr = std::unique_ptr<object, object_deleter>;
    using array_ptr = std::unique_ptr<array, array_deleter>;

    value() noexcept;
    value(std::nullptr_t) noexcept;
    value(bool v) noexcept;
    value(const char* v);
    value(std::string_view v);
    value(std::string v);
    value(const object& v);
    value(object&& v);
    value(const array& v);
    value(array&& v);
    value(const value& other);
    value(value&& other) noexcept;
    value& operator=(const value& other);
    value& operator=(value&& other) noexcept;
    ~value();

    template <typename T>
        requires (std::is_integral_v<T> && std::is_signed_v<T> && !std::is_same_v<T, bool>)
    value(T v) noexcept : data_(static_cast<int64_t>(v)) {}

    template <typename T>
        requires (std::is_integral_v<T> && std::is_unsigned_v<T> && !std::is_same_v<T, bool>)
    value(T v) noexcept : data_(static_cast<uint64_t>(v)) {}

    value(double v) noexcept;

    [[nodiscard]] bool is_null() const noexcept;
    [[nodiscard]] bool is_bool() const noexcept;
    [[nodiscard]] bool is_string() const noexcept;
    [[nodiscard]] bool is_int64() const noexcept;
    [[nodiscard]] bool is_uint64() const noexcept;
    [[nodiscard]] bool is_double() const noexcept;
    [[nodiscard]] bool is_object() const noexcept;
    [[nodiscard]] bool is_array() const noexcept;

    [[nodiscard]] bool as_bool() const;
    [[nodiscard]] const std::string& as_string() const;
    [[nodiscard]] int64_t as_int64() const;
    [[nodiscard]] uint64_t as_uint64() const;
    [[nodiscard]] double as_double() const;
    [[nodiscard]] object& as_object();
    [[nodiscard]] const object& as_object() const;
    [[nodiscard]] array& as_array();
    [[nodiscard]] const array& as_array() const;

    [[nodiscard]] bool operator==(const value& other) const noexcept;
    [[nodiscard]] bool operator!=(const value& other) const noexcept {
        return !(*this == other);
    }

    // 以实际类型访问取值；object/array 以引用传入，不暴露内部指针。
    template <typename Visitor>
    decltype(auto) visit(Visitor&& visitor) const {
        return std::visit([&](const auto& alternative) -> decltype(auto) {
            using Alternative = std::decay_t<decltype(alternative)>;
            if constexpr (std::is_same_v<Alternative, object_ptr> ||
                          std::is_same_v<Alternative, array_ptr>) {
                return visitor(*alternative);
            } else {
                return visitor(alternative);
            }
        }, data_);
    }

private:
    using data_type = std::variant<std::nullptr_t, bool, int64_t, uint64_t, double,
                                   std::string, object_ptr, array_ptr>;
    data_type data_;
};

class object {
public:
    struct key_compare {
        using is_transparent = void;

        KeyComparison comparison = KeyComparison::CaseSensitive;

        [[nodiscard]] bool operator()(std::string_view lhs,
                                      std::string_view rhs) const noexcept;
    };

    using storage_type = std::map<std::string, value, key_compare>;
    using iterator = storage_type::iterator;
    using const_iterator = storage_type::const_iterator;

    object();
    explicit object(KeyComparison comparison);
    object(std::initializer_list<std::pair<std::string, value>> init);
    object(const object& other);
    object(object&& other) noexcept;
    object& operator=(const object& other);
    object& operator=(object&& other) noexcept;
    ~object();

    [[nodiscard]] bool contains(std::string_view key) const;
    [[nodiscard]] value* if_contains(std::string_view key);
    [[nodiscard]] const value* if_contains(std::string_view key) const;

    [[nodiscard]] value& at(std::string_view key);
    [[nodiscard]] const value& at(std::string_view key) const;
    [[nodiscard]] value& operator[](std::string key);
    std::pair<iterator, bool> insert_or_assign(std::string key, value item);

    [[nodiscard]] iterator begin() noexcept { return values_.begin(); }
    [[nodiscard]] iterator end() noexcept { return values_.end(); }
    [[nodiscard]] const_iterator begin() const noexcept { return values_.begin(); }
    [[nodiscard]] const_iterator end() const noexcept { return values_.end(); }

    [[nodiscard]] bool empty() const noexcept { return values_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return values_.size(); }

    [[nodiscard]] bool operator==(const object& other) const noexcept;
    [[nodiscard]] bool operator!=(const object& other) const noexcept {
        return !(*this == other);
    }

private:
    storage_type values_;
};

class array {
public:
    using storage_type = std::vector<value>;
    using iterator = storage_type::iterator;
    using const_iterator = storage_type::const_iterator;

    array();
    array(std::initializer_list<value> init);
    array(const array& other);
    array(array&& other) noexcept;
    array& operator=(const array& other);
    array& operator=(array&& other) noexcept;
    ~array();

    void push_back(value v);
    [[nodiscard]] value& operator[](size_t index);
    [[nodiscard]] const value& operator[](size_t index) const;

    [[nodiscard]] iterator begin() noexcept { return values_.begin(); }
    [[nodiscard]] iterator end() noexcept { return values_.end(); }
    [[nodiscard]] const_iterator begin() const noexcept { return values_.begin(); }
    [[nodiscard]] const_iterator end() const noexcept { return values_.end(); }

    [[nodiscard]] bool empty() const noexcept { return values_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return values_.size(); }

    [[nodiscard]] bool operator==(const array& other) const noexcept;
    [[nodiscard]] bool operator!=(const array& other) const noexcept {
        return !(*this == other);
    }

private:
    storage_type values_;
};

// Applies comparison to every object, including those nested in arrays.
// AsciiCaseInsensitive stores ASCII-lowercase keys without changing string
// values; CaseSensitive preserves key spelling. Keys equal under the chosen
// comparison are duplicates and reject the document, as does nesting deeper
// than 128 arrays/objects.
[[nodiscard]] value parse(
    std::string_view text,
    KeyComparison comparison = KeyComparison::CaseSensitive);
[[nodiscard]] std::string serialize(const value& v);

}  // namespace json

// 配置加载器统一在此将值语义的字段错误转换为 invalid_argument。
namespace infra {

template <typename T>
T RequireJson(tl::expected<T, std::string> result) {
    if (!result) {
        throw std::invalid_argument(std::move(result.error()));
    }
    if constexpr (!std::is_void_v<T>) {
        return std::move(*result);
    }
}

// 只用于本地配置；远端协议对象保留各自的扩展字段接收语义。
void RequireJsonKeys(
    const json::object& source,
    std::initializer_list<std::string_view> allowed,
    std::string_view path,
    std::initializer_list<std::string_view> additional = {});

// Typed readers for one object member. A missing key yields an empty optional
// (or nullptr); a present key with the wrong type, including JSON null, is an
// error, so callers apply defaults only to absent fields.

// The parser stores integers up to INT64_MAX as int64 and larger ones as
// uint64; this is the single conversion of either form to a non-negative value.
[[nodiscard]] std::optional<uint64_t> JsonUnsignedInteger(
    const json::value& value) noexcept;

[[nodiscard]] tl::expected<std::optional<bool>, std::string>
ParseJsonBool(const json::object& source, std::string_view key);

[[nodiscard]] tl::expected<std::optional<std::string>, std::string>
ParseJsonString(const json::object& source, std::string_view key);

[[nodiscard]]
tl::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(const json::object& source, std::string_view key);

[[nodiscard]] tl::expected<std::optional<uint64_t>, std::string>
ParseJsonUint64(
    const json::object& source,
    std::string_view key,
    uint64_t maximum = std::numeric_limits<uint64_t>::max());

// The returned object borrows from source and is valid only while source
// remains alive and unmodified.
[[nodiscard]] tl::expected<const json::object*, std::string>
ParseJsonObject(const json::object& source, std::string_view key);

// Throwing forms for configuration loaders that report errors as
// std::invalid_argument; the fallback applies only to an absent key.
[[nodiscard]] std::string JsonStringOr(
    const json::object& source, std::string_view key, std::string_view fallback);
[[nodiscard]] bool JsonBoolOr(
    const json::object& source, std::string_view key, bool fallback);

enum class JsonPortError {
    None,
    Missing,
    InvalidType,
    OutOfRange,
};

struct JsonPortResult {
    JsonPortError error = JsonPortError::Missing;
    uint16_t value = 0;

    [[nodiscard]] bool Valid() const noexcept {
        return error == JsonPortError::None;
    }

};

[[nodiscard]] JsonPortResult ReadJsonPort(
    const json::object& source, std::string_view key) noexcept;

}  // namespace infra
