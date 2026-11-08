#pragma once

#include <cstdint>
#include <initializer_list>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
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
    [[nodiscard]] bool is_number() const noexcept;
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
    [[nodiscard]] const_iterator cbegin() const noexcept { return values_.cbegin(); }
    [[nodiscard]] const_iterator cend() const noexcept { return values_.cend(); }

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
    [[nodiscard]] const_iterator cbegin() const noexcept { return values_.cbegin(); }
    [[nodiscard]] const_iterator cend() const noexcept { return values_.cend(); }

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
