#include "ss_outbound_uot.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using acpp::SsUotVersion;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

auto Parse(std::string_view body) {
    const auto parsed = acpp::json::parse(body);
    return acpp::proxy::shadowsocks::outbound::ParseUotVersion(
        parsed.as_object());
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid UoT settings were accepted");
    Check(result.error().find(cause) != std::string::npos,
          "UoT settings error lost its cause");
}

void TestValidFormsAreNormalized() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent UoT was enabled");

    auto disabled = Parse(R"({"uot":false})");
    Check(disabled.has_value() && !*disabled, "disabled UoT was enabled");

    auto default_version = Parse(R"({"uot":true})");
    Check(default_version.has_value() &&
              *default_version == SsUotVersion::V2,
          "boolean UoT did not default to v2");

    auto v1 = Parse(R"({"uot":true,"uot_version":1})");
    Check(v1.has_value() && *v1 == SsUotVersion::V1,
          "boolean UoT v1 mismatch");

    auto object = Parse(
        R"({"udp_over_tcp":{"enabled":true,"version":2}})");
    Check(object.has_value() && *object == SsUotVersion::V2,
          "object UoT v2 mismatch");

    auto equal_aliases = Parse(
        R"({"uot":true,"udp_over_tcp":{"enabled":true,"version":2}})");
    Check(equal_aliases.has_value() && *equal_aliases == SsUotVersion::V2,
          "equivalent UoT aliases were rejected");
}

void TestInvalidFormsAreRejected() {
    CheckInvalid(R"({"uot":true,"uotVersion":3})", "must be 1 or 2");
    CheckInvalid(R"({"uot":"true"})", "must be a boolean or object");
    CheckInvalid(
        R"({"udp_over_tcp":{"enabled":true,"version":3}})",
        "must be 1 or 2");
    CheckInvalid(
        R"({"udp_over_tcp":{"enabled":1,"version":2}})",
        "enabled must be a boolean");
    CheckInvalid(
        R"({"uot":false,"udp_over_tcp":true})",
        "must describe the same state");
    CheckInvalid(
        R"({"uot":true,"uotVersion":1,"uot_version":2})",
        "must match");
    CheckInvalid(R"({"uotVersion":2})", "requires uot");
    CheckInvalid(R"({"uot":1})", "must be a boolean or object");
    CheckInvalid(
        R"({"uot":false,"uotVersion":2})",
        "disabled but a UoT version");
}

}  // namespace

int main() {
    TestValidFormsAreNormalized();
    TestInvalidFormsAreRejected();
    std::cout << "ss_outbound_uot_test: ok\n";
    return 0;
}
