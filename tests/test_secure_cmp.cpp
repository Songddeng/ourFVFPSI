#include <iostream>
#include <string>
#include <algorithm>
#include <vector>

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/block.h"
#include "newcmp.h"
#include "neweq.h"

using namespace osuCrypto;

namespace {

Role parseRole(const CLP& cmd)
{
    if (cmd.isSet("receiver")) {
        return Role::Receiver;
    }
    return Role::Sender;
}

void printBits(const BitVector& bits)
{
    for (u64 i = 0; i < bits.size(); ++i) {
        std::cout << static_cast<int>(bits[i]) << '\n';
    }
}

}  // namespace

uint8_t Zp::p;

int main(int argc, char** argv)
{
    CLP cmd;
    cmd.parse(argc, argv);

    const Role role = parseRole(cmd);
    const auto ip = cmd.getOr<std::string>("ip", "localhost:1213");
    const auto num = cmd.getOr<int>("n", 8);
    const auto ell = cmd.getOr<int>("l", 4);
    const auto iscmp = cmd.getOr<int>("c", 1);

    if (iscmp == 0) {
        std::vector<block> data(num, toBlock(0, 0));
        BitVector output(num);
        eq2<uint8_t> eq(role, ip, nullptr, nullptr);
        eq.run(data, output, ell);
        printBits(output);
        return 0;
    }

    std::vector<block> data(num, toBlock(0, 10));
    const auto modBase = 1ULL << std::min(ell, 20);
    if (role == Role::Receiver) {
        for (int i = 0; i < num; ++i) {
            data[i] = toBlock(0, static_cast<u64>((10 + i) % modBase));
        }
    } else {
        for (int i = 0; i < num; ++i) {
            data[i] = toBlock(0, static_cast<u64>((11 - i + modBase) % modBase));
        }
    }

    BitVector output(num);
    cmp1<uint8_t> cmp(role, ip, num, ell);
    cmp.run(data, output, ell);
    printBits(output);
    return 0;
}
