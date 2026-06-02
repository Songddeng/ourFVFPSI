#include "secure_cmp_bridge.h"

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "newcmp.h"

uint8_t Zp::p;

namespace secure_cmp_bridge {

void compare_u64(
    Role role,
    const std::string &ip,
    const std::vector<uint64_t> &input,
    uint32_t ell,
    std::vector<uint8_t> &output,
    Profile *profile)
{
    std::vector<osuCrypto::block> data(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        data[i] = osuCrypto::toBlock(0, input[i]);
    }

    osuCrypto::BitVector cmpOutput(input.size());
    CmpProfile cmpProfile;
    cmp1<uint8_t> cmp(role == Role::Sender ? ::Role::Sender : ::Role::Receiver, ip, static_cast<int>(input.size()), static_cast<int>(ell), &cmpProfile);
    cmp.run(data, cmpOutput, ell);

    if (profile) {
        profile->offline_ms = cmpProfile.offline_ms;
        profile->online_ms = cmpProfile.online_ms;
        profile->offline_comm_bytes = cmpProfile.offline_comm_bytes;
        profile->online_comm_bytes = cmpProfile.online_comm_bytes;
    }

    output.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = static_cast<uint8_t>(cmpOutput[i] & 1);
    }
}

} // namespace secure_cmp_bridge
