#include "common/process_resources.hpp"

#include <cstdio>
#include <type_traits>

#include <fcntl.h>
#include <unistd.h>

static_assert(std::is_aggregate_v<acpp::ProcessDescriptors>);
static_assert(noexcept(acpp::ReadProcessDescriptors()));

int main() {
    const auto before = acpp::ReadProcessDescriptors();
    const int resource = ::open("/dev/null", O_RDONLY);
    if (resource < 0) return 1;
    const auto during = acpp::ReadProcessDescriptors();
    ::close(resource);
    const auto after = acpp::ReadProcessDescriptors();
    if (!before.open || !during.open || !after.open ||
        *during.open != *before.open + 1 || *after.open != *before.open) return 3;
    rlimit limits{};
    if (::getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        if (limits.rlim_cur == RLIM_INFINITY) {
            if (!before.soft_limit_unlimited || before.soft_limit) return 4;
        } else if (before.soft_limit_unlimited || !before.soft_limit ||
                   *before.soft_limit != static_cast<size_t>(limits.rlim_cur)) return 5;
    }
    std::printf("process descriptor sampling: open=%zu\n", before.open.value_or(0));
    return 0;
}
