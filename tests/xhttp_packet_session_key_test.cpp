#include "xhttp_packet_session_key.hpp"

#include <cstdlib>
#include <unordered_map>

int main() {
    acpp::net::io_context first_context;
    acpp::net::io_context second_context;

    using Key = acpp::detail::XHttpPacketSessionKey;
    using Map = std::unordered_map<
        Key,
        int,
        acpp::detail::XHttpPacketSessionKeyHash,
        acpp::detail::XHttpPacketSessionKeyEq>;
    Map sessions;

    Key first{.owner = &first_context};
    first.session_id = "shared-session";
    Key second{.owner = &second_context};
    second.session_id = "shared-session";
    sessions.emplace(std::move(first), 1);
    sessions.emplace(std::move(second), 2);

    const auto first_it = sessions.find(acpp::detail::XHttpPacketSessionKeyRef{
        &first_context, "shared-session"});
    const auto second_it = sessions.find(acpp::detail::XHttpPacketSessionKeyRef{
        &second_context, "shared-session"});
    if (sessions.size() != 2 || first_it == sessions.end() ||
        second_it == sessions.end() || first_it->second != 1 ||
        second_it->second != 2) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
