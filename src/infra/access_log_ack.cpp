#include "access_log_ack.hpp"

#include "acppnode/infra/json.hpp"

namespace acpp::accesslog::detail {

bool IsBatchAcknowledged(
    int status,
    std::string_view body,
    std::string_view expected_batch_id) noexcept {
    if ((status != 200 && status != 409) || expected_batch_id.empty()) {
        return false;
    }

    try {
        const json::value parsed = json::parse(body);
        if (!parsed.is_object()) {
            return false;
        }
        const json::object& object = parsed.as_object();
        const json::value* accepted = object.if_contains("accepted");
        const json::value* batch_id = object.if_contains("batch_id");
        return accepted && accepted->is_bool() && accepted->as_bool() &&
               batch_id && batch_id->is_string() &&
               batch_id->as_string() == expected_batch_id;
    } catch (...) {
        return false;
    }
}

}  // namespace acpp::accesslog::detail
