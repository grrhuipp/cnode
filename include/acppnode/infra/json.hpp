#pragma once

#include <cstdint>
#include <initializer_list>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace acpp::json {

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

private:
    using data_type = std::variant<std::nullptr_t, bool, int64_t, uint64_t, double,
                                   std::string, object_ptr, array_ptr>;
    data_type data_;
};

class object {
public:
    using storage_type = std::map<std::string, value, std::less<>>;
    using iterator = storage_type::iterator;
    using const_iterator = storage_type::const_iterator;

    object();
    object(std::initializer_list<std::pair<std::string, value>> init);

    [[nodiscard]] bool contains(std::string_view key) const;
    [[nodiscard]] value* if_contains(std::string_view key);
    [[nodiscard]] const value* if_contains(std::string_view key) const;

    [[nodiscard]] value& at(std::string_view key);
    [[nodiscard]] const value& at(std::string_view key) const;
    [[nodiscard]] value& operator[](std::string key);

    [[nodiscard]] iterator begin() noexcept { return values_.begin(); }
    [[nodiscard]] iterator end() noexcept { return values_.end(); }
    [[nodiscard]] const_iterator begin() const noexcept { return values_.begin(); }
    [[nodiscard]] const_iterator end() const noexcept { return values_.end(); }
    [[nodiscard]] const_iterator cbegin() const noexcept { return values_.cbegin(); }
    [[nodiscard]] const_iterator cend() const noexcept { return values_.cend(); }

    [[nodiscard]] bool empty() const noexcept { return values_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return values_.size(); }

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

private:
    storage_type values_;
};

[[nodiscard]] value parse(std::string_view text);
[[nodiscard]] std::string serialize(const value& v);

}  // namespace acpp::json
