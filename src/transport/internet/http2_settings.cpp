#include "http2_settings.hpp"

namespace acpp::transport::internet {

memory::ByteVector EncodeInitialWindowSetting(uint32_t initial_window) {
    memory::ByteVector payload(6);
    payload[0] = 0;
    payload[1] = 4;  // SETTINGS_INITIAL_WINDOW_SIZE
    payload[2] = static_cast<uint8_t>(initial_window >> 24);
    payload[3] = static_cast<uint8_t>(initial_window >> 16);
    payload[4] = static_cast<uint8_t>(initial_window >> 8);
    payload[5] = static_cast<uint8_t>(initial_window);
    return payload;
}

}  // namespace acpp::transport::internet
