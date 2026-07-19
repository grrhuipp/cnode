#include "acppnode/infra/json.hpp"

#include <charconv>
#include <cmath>
#include <format>
#include <limits>

namespace acpp::json {

void object_deleter::operator()(object* ptr) const noexcept {
    delete ptr;
}

void array_deleter::operator()(array* ptr) const noexcept {
    delete ptr;
}

object::object() = default;

object::object(std::initializer_list<std::pair<std::string, value>> init) {
    for (auto& [key, val] : init) {
        values_.emplace(key, val);
    }
}

bool object::contains(std::string_view key) const {
    return values_.find(key) != values_.end();
}

value* object::if_contains(std::string_view key) {
    auto it = values_.find(key);
    return it == values_.end() ? nullptr : &it->second;
}

const value* object::if_contains(std::string_view key) const {
    auto it = values_.find(key);
    return it == values_.end() ? nullptr : &it->second;
}

value& object::at(std::string_view key) {
    auto it = values_.find(key);
    if (it == values_.end()) throw std::out_of_range("json object key not found");
    return it->second;
}

const value& object::at(std::string_view key) const {
    auto it = values_.find(key);
    if (it == values_.end()) throw std::out_of_range("json object key not found");
    return it->second;
}

value& object::operator[](std::string key) {
    return values_[std::move(key)];
}

array::array() = default;
array::array(std::initializer_list<value> init) : values_(init) {}

void array::push_back(value v) {
    values_.push_back(std::move(v));
}

value& array::operator[](size_t index) {
    return values_[index];
}

const value& array::operator[](size_t index) const {
    return values_[index];
}

value::value() noexcept : data_(nullptr) {}
value::value(std::nullptr_t) noexcept : data_(nullptr) {}
value::value(bool v) noexcept : data_(v) {}
value::value(const char* v) : data_(std::string(v ? v : "")) {}
value::value(std::string_view v) : data_(std::string(v)) {}
value::value(std::string v) : data_(std::move(v)) {}
value::value(const object& v) : data_(object_ptr(new object(v))) {}
value::value(object&& v) : data_(object_ptr(new object(std::move(v)))) {}
value::value(const array& v) : data_(array_ptr(new array(v))) {}
value::value(array&& v) : data_(array_ptr(new array(std::move(v)))) {}
value::value(const value& other) : data_(nullptr) {
    if (other.is_null()) {
        data_ = nullptr;
    } else if (other.is_bool()) {
        data_ = other.as_bool();
    } else if (other.is_int64()) {
        data_ = other.as_int64();
    } else if (other.is_uint64()) {
        data_ = other.as_uint64();
    } else if (other.is_double()) {
        data_ = other.as_double();
    } else if (other.is_string()) {
        data_ = other.as_string();
    } else if (other.is_object()) {
        data_ = object_ptr(new object(other.as_object()));
    } else if (other.is_array()) {
        data_ = array_ptr(new array(other.as_array()));
    }
}
value::value(value&& other) noexcept = default;
value& value::operator=(const value& other) {
    if (this != &other) {
        *this = value(other);
    }
    return *this;
}
value& value::operator=(value&& other) noexcept = default;
value::~value() = default;
value::value(double v) noexcept : data_(v) {}

bool value::is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(data_); }
bool value::is_bool() const noexcept { return std::holds_alternative<bool>(data_); }
bool value::is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
bool value::is_int64() const noexcept { return std::holds_alternative<int64_t>(data_); }
bool value::is_uint64() const noexcept { return std::holds_alternative<uint64_t>(data_); }
bool value::is_double() const noexcept { return std::holds_alternative<double>(data_); }
bool value::is_number() const noexcept { return is_int64() || is_uint64() || is_double(); }
bool value::is_object() const noexcept { return std::holds_alternative<object_ptr>(data_); }
bool value::is_array() const noexcept { return std::holds_alternative<array_ptr>(data_); }

bool value::as_bool() const { return std::get<bool>(data_); }
const std::string& value::as_string() const { return std::get<std::string>(data_); }
int64_t value::as_int64() const { return std::get<int64_t>(data_); }
uint64_t value::as_uint64() const { return std::get<uint64_t>(data_); }
double value::as_double() const {
    if (is_double()) return std::get<double>(data_);
    if (is_int64()) return static_cast<double>(as_int64());
    if (is_uint64()) return static_cast<double>(as_uint64());
    throw std::bad_variant_access();
}
object& value::as_object() { return *std::get<object_ptr>(data_); }
const object& value::as_object() const { return *std::get<object_ptr>(data_); }
array& value::as_array() { return *std::get<array_ptr>(data_); }
const array& value::as_array() const { return *std::get<array_ptr>(data_); }

namespace {

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    value Parse() {
        SkipWs();
        auto v = ParseValue();
        SkipWs();
        if (pos_ != text_.size()) Fail("trailing characters");
        return v;
    }

private:
    void Fail(std::string_view msg) const {
        throw parse_error(std::format("{} at byte {}", msg, pos_));
    }

    [[nodiscard]] char Peek() const {
        return pos_ < text_.size() ? text_[pos_] : '\0';
    }

    char Take() {
        if (pos_ >= text_.size()) Fail("unexpected end of input");
        return text_[pos_++];
    }

    bool Consume(char c) {
        if (Peek() != c) return false;
        ++pos_;
        return true;
    }

    void Expect(char c) {
        if (!Consume(c)) Fail(std::format("expected '{}'", c));
    }

    void SkipWs() {
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t') break;
            ++pos_;
        }
    }

    value ParseValue() {
        SkipWs();
        switch (Peek()) {
            case '{': return ParseObject();
            case '[': return ParseArray();
            case '"': return ParseString();
            case 't': return ParseLiteral("true", value(true));
            case 'f': return ParseLiteral("false", value(false));
            case 'n': return ParseLiteral("null", value(nullptr));
            default:
                if (Peek() == '-' || (Peek() >= '0' && Peek() <= '9')) {
                    return ParseNumber();
                }
                Fail("expected JSON value");
                return value(nullptr);
        }
    }

    value ParseLiteral(std::string_view literal, value v) {
        if (text_.substr(pos_, literal.size()) != literal) {
            Fail("invalid literal");
        }
        pos_ += literal.size();
        return v;
    }

    object ParseObject() {
        object obj;
        Expect('{');
        SkipWs();
        if (Consume('}')) return obj;

        while (true) {
            SkipWs();
            if (Peek() != '"') Fail("expected object key");
            std::string key = ParseString().as_string();
            SkipWs();
            Expect(':');
            obj[std::move(key)] = ParseValue();
            SkipWs();
            if (Consume('}')) return obj;
            Expect(',');
        }
    }

    array ParseArray() {
        array arr;
        Expect('[');
        SkipWs();
        if (Consume(']')) return arr;

        while (true) {
            arr.push_back(ParseValue());
            SkipWs();
            if (Consume(']')) return arr;
            Expect(',');
        }
    }

    value ParseString() {
        Expect('"');
        std::string out;

        while (true) {
            const char c = Take();
            if (c == '"') return value(std::move(out));
            if (static_cast<unsigned char>(c) < 0x20) Fail("control character in string");
            if (c != '\\') {
                out.push_back(c);
                continue;
            }

            switch (Take()) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': AppendUnicodeEscape(out); break;
                default: Fail("invalid string escape");
            }
        }
    }

    void AppendUnicodeEscape(std::string& out) {
        uint32_t code_point = ReadHex4();
        if (code_point >= 0xD800 && code_point <= 0xDBFF) {
            if (!Consume('\\') || !Consume('u')) {
                Fail("high surrogate without low surrogate");
            }
            const uint32_t low_surrogate = ReadHex4();
            if (low_surrogate < 0xDC00 || low_surrogate > 0xDFFF) {
                Fail("high surrogate without low surrogate");
            }
            code_point = 0x10000 + ((code_point - 0xD800) << 10) +
                         (low_surrogate - 0xDC00);
        } else if (code_point >= 0xDC00 && code_point <= 0xDFFF) {
            Fail("low surrogate without high surrogate");
        }
        AppendUtf8(code_point, out);
    }

    uint32_t ReadHex4() {
        uint32_t cp = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = Take();
            cp <<= 4;
            if (c >= '0' && c <= '9') cp |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') cp |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') cp |= static_cast<uint32_t>(c - 'A' + 10);
            else Fail("invalid unicode escape");
        }
        return cp;
    }

    static void AppendUtf8(uint32_t cp, std::string& out) {
        if (cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    value ParseNumber() {
        const size_t start = pos_;
        if (Consume('-')) {}
        if (Consume('0')) {
        } else {
            if (Peek() < '1' || Peek() > '9') Fail("invalid number");
            while (Peek() >= '0' && Peek() <= '9') ++pos_;
        }

        bool floating = false;
        if (Consume('.')) {
            floating = true;
            if (Peek() < '0' || Peek() > '9') Fail("invalid fraction");
            while (Peek() >= '0' && Peek() <= '9') ++pos_;
        }
        if (Peek() == 'e' || Peek() == 'E') {
            floating = true;
            ++pos_;
            if (Peek() == '+' || Peek() == '-') ++pos_;
            if (Peek() < '0' || Peek() > '9') Fail("invalid exponent");
            while (Peek() >= '0' && Peek() <= '9') ++pos_;
        }

        const auto token = text_.substr(start, pos_ - start);
        if (floating) {
            double d = 0.0;
            auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), d);
            if (ec != std::errc{} || ptr != token.data() + token.size()) Fail("invalid number");
            return value(d);
        }

        if (!token.empty() && token[0] == '-') {
            int64_t n = 0;
            auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), n);
            if (ec != std::errc{} || ptr != token.data() + token.size()) Fail("invalid integer");
            return value(n);
        }

        uint64_t n = 0;
        auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), n);
        if (ec != std::errc{} || ptr != token.data() + token.size()) Fail("invalid integer");
        if (n <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            return value(static_cast<int64_t>(n));
        }
        return value(n);
    }

    std::string_view text_;
    size_t pos_ = 0;
};

void SerializeString(const std::string& s, std::string& out) {
    out.push_back('"');
    for (const unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += std::format("\\u{:04x}", c);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

void SerializeValue(const value& v, std::string& out) {
    if (v.is_null()) {
        out += "null";
    } else if (v.is_bool()) {
        out += v.as_bool() ? "true" : "false";
    } else if (v.is_int64()) {
        out += std::to_string(v.as_int64());
    } else if (v.is_uint64()) {
        out += std::to_string(v.as_uint64());
    } else if (v.is_double()) {
        out += std::format("{}", v.as_double());
    } else if (v.is_string()) {
        SerializeString(v.as_string(), out);
    } else if (v.is_array()) {
        out.push_back('[');
        bool first = true;
        for (const auto& item : v.as_array()) {
            if (!first) out.push_back(',');
            first = false;
            SerializeValue(item, out);
        }
        out.push_back(']');
    } else {
        out.push_back('{');
        bool first = true;
        for (const auto& [key, item] : v.as_object()) {
            if (!first) out.push_back(',');
            first = false;
            SerializeString(key, out);
            out.push_back(':');
            SerializeValue(item, out);
        }
        out.push_back('}');
    }
}

}  // namespace

value parse(std::string_view text) {
    return Parser(text).Parse();
}

std::string serialize(const value& v) {
    std::string out;
    SerializeValue(v, out);
    return out;
}

}  // namespace acpp::json
