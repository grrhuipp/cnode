#include <openssl/bio.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>

extern "C" int cnode_release_empty_bio_pair_buffers(BIO* bio);

int main() {
    BIO* raw_a = nullptr;
    BIO* raw_b = nullptr;
    if (BIO_new_bio_pair(&raw_a, 0, &raw_b, 0) != 1) return 1;
    std::unique_ptr<BIO, decltype(&BIO_free)> a(raw_a, BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> b(raw_b, BIO_free);

    constexpr long kRecordCapacity = 17 * 1024;
    if (BIO_ctrl(a.get(), BIO_C_GET_WRITE_BUF_SIZE, 0, nullptr) != kRecordCapacity ||
        BIO_ctrl(b.get(), BIO_C_GET_WRITE_BUF_SIZE, 0, nullptr) != kRecordCapacity ||
        cnode_release_empty_bio_pair_buffers(a.get()) != 2 ||
        cnode_release_empty_bio_pair_buffers(b.get()) != 0 ||
        BIO_ctrl_get_write_guarantee(a.get()) != kRecordCapacity) {
        return 2;
    }

    const char first[] = "preserve queued encrypted bytes";
    std::array<char, 64> output{};
    if (BIO_write(a.get(), first, sizeof(first)) != sizeof(first) ||
        cnode_release_empty_bio_pair_buffers(a.get()) != 0 ||
        BIO_read(b.get(), output.data(), static_cast<int>(output.size())) != sizeof(first) ||
        std::memcmp(output.data(), first, sizeof(first)) != 0 ||
        cnode_release_empty_bio_pair_buffers(b.get()) != 1) {
        return 3;
    }

    const char second[] = "read and write after idle release";
    output.fill(0);
    if (BIO_write(b.get(), second, sizeof(second)) != sizeof(second) ||
        BIO_read(a.get(), output.data(), static_cast<int>(output.size())) != sizeof(second) ||
        std::memcmp(output.data(), second, sizeof(second)) != 0 ||
        cnode_release_empty_bio_pair_buffers(a.get()) != 1 ||
        BIO_ctrl(a.get(), BIO_C_GET_WRITE_BUF_SIZE, 0, nullptr) != kRecordCapacity ||
        BIO_ctrl(b.get(), BIO_C_GET_WRITE_BUF_SIZE, 0, nullptr) != kRecordCapacity) {
        return 4;
    }
    return 0;
}
