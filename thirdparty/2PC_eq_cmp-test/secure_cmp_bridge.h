#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace secure_cmp_bridge {

enum class Role {
    Sender,
    Receiver
};

struct Profile {
    double offline_ms = 0.0;
    double online_ms = 0.0;
    uint64_t offline_comm_bytes = 0;
    uint64_t online_comm_bytes = 0;
};

void compare_u64(
    Role role,
    const std::string &ip,
    const std::vector<uint64_t> &input,
    uint32_t ell,
    std::vector<uint8_t> &output,
    Profile *profile = nullptr);

} // namespace secure_cmp_bridge
