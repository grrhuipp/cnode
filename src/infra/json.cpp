#include "infra/json.hpp"
#include "common/ascii.hpp"
#include "common/binary_text_codec.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <format>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <utility>
namespace infra {

void object_deleter::operator()(object* ptr) const noexcept {
    delete ptr;
}

void array_deleter::operator()(array* ptr) const noexcept {
    delete ptr;
}

namespace {

void NormalizeKey(std::string& key, KeyComparison comparison) noexcept {
    if (comparison != KeyComparison::AsciiCaseInsensitive) return;
    common::LowerAsciiInPlace(key);
}

}  // namespace

bool object::key_compare::operator()(std::string_view lhs,
                                     std::string_view rhs) const noexcept {
    if (comparison == KeyComparison::CaseSensitive) return lhs < rhs;
    return std::ranges::lexicographical_compare(
        lhs, rhs, {},
        [](char ch) { return common::ToLowerAscii(static_cast<unsigned char>(ch)); },
        [](char ch) { return common::ToLowerAscii(static_cast<unsigned char>(ch)); });
}

object::object() = default;
object::object(KeyComparison comparison) : values_(key_compare{comparison}) {}

object::object(std::initializer_list<std::pair<std::string, value>> init) {
    for (auto& [key, val] : init) {
        values_.emplace(key, val);
    }
}

object::object(const object& other) = default;
object::object(object&& other) noexcept = default;

object& object::operator=(const object& other) {
    if (this != &other) {
        object copy(other);
        values_.swap(copy.values_);
    }
    return *this;
}

object& object::operator=(object&& other) noexcept {
    if (this != &other) {
        object moved(std::move(other));
        values_.swap(moved.values_);
    }
    return *this;
}

object::~object() = default;

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
    NormalizeKey(key, values_.key_comp().comparison);
    return values_[std::move(key)];
}

std::pair<object::iterator, bool> object::insert_or_assign(std::string key, value item) {
    NormalizeKey(key, values_.key_comp().comparison);
    return values_.insert_or_assign(std::move(key), std::move(item));
}

bool object::operator==(const object& other) const noexcept {
    return values_ == other.values_;
}

array::array() = default;
array::array(std::initializer_list<value> init) : values_(init) {}
array::array(const array& other) = default;
array::array(array&& other) noexcept = default;

array& array::operator=(const array& other) {
    if (this != &other) {
        array copy(other);
        values_.swap(copy.values_);
    }
    return *this;
}

array& array::operator=(array&& other) noexcept {
    if (this != &other) {
        array moved(std::move(other));
        values_.swap(moved.values_);
    }
    return *this;
}

array::~array() = default;

void array::push_back(value v) {
    values_.push_back(std::move(v));
}

value& array::operator[](size_t index) {
    return values_[index];
}

const value& array::operator[](size_t index) const {
    return values_[index];
}

bool array::operator==(const array& other) const noexcept {
    return values_ == other.values_;
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
value::value(const value& other)
    : data_(std::visit([](const auto& alternative) -> data_type {
          using Alternative = std::decay_t<decltype(alternative)>;
          if constexpr (std::is_same_v<Alternative, object_ptr>) {
              return object_ptr(new object(*alternative));
          } else if constexpr (std::is_same_v<Alternative, array_ptr>) {
              return array_ptr(new array(*alternative));
          } else {
              return alternative;
          }
      }, other.data_)) {}
value::value(value&& other) noexcept = default;
value& value::operator=(const value& other) {
    if (this != &other) {
        data_ = value(other).data_;
    }
    return *this;
}
value& value::operator=(value&& other) noexcept {
    if (this != &other) {
        value moved(std::move(other));
        data_.swap(moved.data_);
    }
    return *this;
}
value::~value() = default;
value::value(double v) noexcept : data_(v) {}

bool value::is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(data_); }
bool value::is_bool() const noexcept { return std::holds_alternative<bool>(data_); }
bool value::is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
bool value::is_int64() const noexcept { return std::holds_alternative<int64_t>(data_); }
bool value::is_uint64() const noexcept { return std::holds_alternative<uint64_t>(data_); }
bool value::is_double() const noexcept { return std::holds_alternative<double>(data_); }
bool value::is_object() const noexcept { return std::holds_alternative<object_ptr>(data_); }
bool value::is_array() const noexcept { return std::holds_alternative<array_ptr>(data_); }

bool value::as_bool() const { return std::get<bool>(data_); }
std::string& value::as_string() { return std::get<std::string>(data_); }
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

bool value::operator==(const value& other) const noexcept {
    if (is_null()) return other.is_null();
    if (is_bool()) return other.is_bool() && as_bool() == other.as_bool();
    if (is_string()) return other.is_string() && as_string() == other.as_string();
    if (is_int64()) {
        if (other.is_int64()) return as_int64() == other.as_int64();
        if (other.is_uint64()) {
            return as_int64() >= 0 &&
                   static_cast<uint64_t>(as_int64()) == other.as_uint64();
        }
        return false;
    }
    if (is_uint64()) {
        if (other.is_uint64()) return as_uint64() == other.as_uint64();
        if (other.is_int64()) {
            return other.as_int64() >= 0 &&
                   as_uint64() == static_cast<uint64_t>(other.as_int64());
        }
        return false;
    }
    if (is_double()) return other.is_double() && as_double() == other.as_double();
    if (is_object()) return other.is_object() && as_object() == other.as_object();
    if (is_array()) return other.is_array() && as_array() == other.as_array();
    return false;
}

namespace {

// RFC 8259 §9 lets a parser bound nesting depth. Parsing recurses per level on
// the caller's stack, and panel responses are remote input, so the bound keeps
// a hostile body from exhausting the control-plane thread stack. 128 levels
// (serde_json's default) far exceed every configuration or panel schema.
constexpr size_t kMaxNestingDepth = 128;

class Parser {
public:
    Parser(std::string_view text, KeyComparison comparison)
        : text_(text), comparison_(comparison) {}

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

    void EnterNesting() {
        if (++depth_ > kMaxNestingDepth) Fail("nesting too deep");
    }

    object ParseObject() {
        object obj(comparison_);
        Expect('{');
        EnterNesting();
        SkipWs();
        if (Consume('}')) {
            --depth_;
            return obj;
        }

        while (true) {
            SkipWs();
            if (Peek() != '"') Fail("expected object key");
            const size_t key_position = pos_;
            std::string key = ParseString();
            SkipWs();
            Expect(':');
            // RFC 8259 §4 leaves duplicate names unpredictable across parsers;
            // last-wins would let one field silently shadow another, so any
            // repeat under the active key comparison rejects the document.
            auto [entry, inserted] = obj.insert_or_assign(std::move(key), ParseValue());
            if (!inserted) {
                throw parse_error(std::format(
                    "duplicate object key '{}' at byte {}", entry->first, key_position));
            }
            SkipWs();
            if (Consume('}')) {
                --depth_;
                return obj;
            }
            Expect(',');
        }
    }

    array ParseArray() {
        array arr;
        Expect('[');
        EnterNesting();
        SkipWs();
        if (Consume(']')) {
            --depth_;
            return arr;
        }

        while (true) {
            arr.push_back(ParseValue());
            SkipWs();
            if (Consume(']')) {
                --depth_;
                return arr;
            }
            Expect(',');
        }
    }

    std::string ParseString() {
        Expect('"');
        const size_t first_run = pos_;
        while (pos_ < text_.size()) {
            const char next = text_[pos_];
            if (next == '"') {
                const size_t len = pos_ - first_run;
                ++pos_;
                return std::string(text_.data() + first_run, len);
            }
            if (next == '\\' || static_cast<unsigned char>(next) < 0x20) break;
            ++pos_;
        }

        std::string out(text_.data() + first_run, pos_ - first_run);
        while (true) {
            const char c = Take();
            if (c == '"') return out;
            if (c != '\\') Fail("control character in string");

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

            const size_t run = pos_;
            while (pos_ < text_.size()) {
                const char next = text_[pos_];
                if (next == '"' || next == '\\' || static_cast<unsigned char>(next) < 0x20) break;
                ++pos_;
            }
            out.append(text_.data() + run, pos_ - run);
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
            const int digit = common::HexDigitValue(Take());
            if (digit < 0) Fail("invalid unicode escape");
            cp = (cp << 4) | static_cast<uint32_t>(digit);
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
    KeyComparison comparison_;
    size_t pos_ = 0;
    size_t depth_ = 0;
};

void SerializeString(std::string_view s, std::string& out) {
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
                    constexpr char kHex[] = "0123456789abcdef";
                    const char escaped[6] = {'\\', 'u', '0', '0', kHex[c >> 4], kHex[c & 0x0f]};
                    out.append(escaped, sizeof(escaped));
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

template <typename... Handlers>
struct Overloaded : Handlers... {
    using Handlers::operator()...;
};

void SerializeValue(const value& v, std::string& out) {
    v.visit(Overloaded{
        [&](std::nullptr_t) { out += "null"; },
        [&](bool b) { out += b ? "true" : "false"; },
        [&](int64_t n) {
            char buf[24];
            const auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), n);
            if (ec == std::errc{}) out.append(buf, ptr);
        },
        [&](uint64_t n) {
            char buf[24];
            const auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), n);
            if (ec == std::errc{}) out.append(buf, ptr);
        },
        [&](double d) {
            if (!std::isfinite(d)) {
                throw std::invalid_argument("json number must be finite");
            }
            std::format_to(std::back_inserter(out), "{}", d);
        },
        [&](const std::string& s) { SerializeString(s, out); },
        [&](const array& items) {
            out.push_back('[');
            bool first = true;
            for (const auto& item : items) {
                if (!first) out.push_back(',');
                first = false;
                SerializeValue(item, out);
            }
            out.push_back(']');
        },
        [&](const object& members) {
            out.push_back('{');
            bool first = true;
            for (const auto& [key, item] : members) {
                if (!first) out.push_back(',');
                first = false;
                SerializeString(key, out);
                out.push_back(':');
                SerializeValue(item, out);
            }
            out.push_back('}');
        }
    });
}
}  // namespace

void append_json_string(std::string& out, std::string_view s) {
    SerializeString(s, out);
}

value parse(std::string_view text, KeyComparison comparison) {
    return Parser(text, comparison).Parse();
}

std::string serialize(const value& v) {
    std::string out;
    SerializeValue(v, out);
    return out;
}


std::optional<uint64_t> JsonUnsignedInteger(const infra::value& value) noexcept {
    if (value.is_uint64()) {
        return value.as_uint64();
    }
    if (value.is_int64() && value.as_int64() >= 0) {
        return static_cast<uint64_t>(value.as_int64());
    }
    return std::nullopt;
}

tl::expected<std::optional<bool>, std::string>
ParseJsonBool(const object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<bool>{};
    }
    if (!raw->is_bool()) {
        return tl::unexpected(std::format("{} must be a boolean", key));
    }
    return std::optional<bool>{raw->as_bool()};
}

tl::expected<std::optional<std::string>, std::string>
ParseJsonString(const object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<std::string>{};
    }
    if (!raw->is_string()) {
        return tl::unexpected(std::format("{} must be a string", key));
    }
    return std::optional<std::string>{raw->as_string()};
}

tl::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(const object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<std::vector<std::string>>{};
    }
    if (!raw->is_array()) {
        return tl::unexpected(std::format(
            "{} must be an array of strings", key));
    }

    std::vector<std::string> values;
    values.reserve(raw->as_array().size());
    for (const auto& item : raw->as_array()) {
        if (!item.is_string()) {
            return tl::unexpected(std::format(
                "{} must contain only strings", key));
        }
        values.emplace_back(item.as_string());
    }
    return std::optional<std::vector<std::string>>{std::move(values)};
}

tl::expected<std::optional<uint64_t>, std::string>
ParseJsonUint64(
    const object& source,
    std::string_view key,
    uint64_t maximum) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<uint64_t>{};
    }
    const auto value = JsonUnsignedInteger(*raw);
    if (!value || *value > maximum) {
        return tl::unexpected(std::format(
            "{} must be an integer between 0 and {}", key, maximum));
    }
    return std::optional<uint64_t>{*value};
}

tl::expected<const object*, std::string>
ParseJsonObject(const object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return nullptr;
    }
    if (!raw->is_object()) {
        return tl::unexpected(std::format("{} must be an object", key));
    }
    return &raw->as_object();
}

std::string JsonStringOr(
    const object& source, std::string_view key, std::string_view fallback) {
    auto parsed = RequireJson(ParseJsonString(source, key));
    if (parsed) return std::move(*parsed);
    return std::string(fallback);
}

bool JsonBoolOr(const object& source, std::string_view key, bool fallback) {
    return RequireJson(ParseJsonBool(source, key)).value_or(fallback);
}


JsonPortResult ReadJsonPort(
    const object& source, std::string_view key) noexcept {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return {};
    }
    if (!raw->is_int64() && !raw->is_uint64()) {
        return {.error = JsonPortError::InvalidType};
    }
    const auto value = JsonUnsignedInteger(*raw);
    if (!value || *value == 0 || *value > std::numeric_limits<uint16_t>::max()) {
        return {.error = JsonPortError::OutOfRange};
    }
    return {
        .error = JsonPortError::None,
        .value = static_cast<uint16_t>(*value),
    };
}

}  // namespace infra
