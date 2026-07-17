#include "access_log_ack.hpp"

#include <cassert>
#include <string>

int main() {
    using acpp::accesslog::detail::IsBatchAcknowledged;
    constexpr std::string_view batch_id = "00112233445566778899aabbccddeeff";

    assert(IsBatchAcknowledged(
        200,
        R"({"accepted":true,"batch_id":"00112233445566778899aabbccddeeff","acked_through_sequence":7})",
        batch_id));
    assert(IsBatchAcknowledged(
        409,
        R"({"accepted":true,"batch_id":"00112233445566778899aabbccddeeff"})",
        batch_id));

    assert(!IsBatchAcknowledged(
        200,
        R"({"accepted":true,"batch_id":"ffeeddccbbaa99887766554433221100","detail":"00112233445566778899aabbccddeeff"})",
        batch_id));
    assert(!IsBatchAcknowledged(
        409,
        R"({"accepted":false,"batch_id":"00112233445566778899aabbccddeeff"})",
        batch_id));
    assert(!IsBatchAcknowledged(
        200,
        R"({"accepted":"true","batch_id":"00112233445566778899aabbccddeeff"})",
        batch_id));
    assert(!IsBatchAcknowledged(200, "not json", batch_id));
    assert(!IsBatchAcknowledged(
        503,
        R"({"accepted":true,"batch_id":"00112233445566778899aabbccddeeff"})",
        batch_id));
    return 0;
}
