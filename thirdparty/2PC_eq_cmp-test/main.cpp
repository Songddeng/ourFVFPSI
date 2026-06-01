#include <iostream>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/CLP.h"
#include "neweq.h"
#include "newcmp.h"
#include "utils.h"

using namespace std;
using namespace osuCrypto;


uint8_t Zp::p;

// int p;
Timer::timeUnit encode_start, encode_end;

int main(int argc, char* argv[]) {
    CLP cmd;
    cmd.parse(argc, argv);

    Role role;

    if (cmd.isSet("sender")) {
        role = Role::Sender;
    } else if (cmd.isSet("receiver")) {
        role = Role::Receiver;
    } else {
        role = Role::Sender;
    }

    auto ip = cmd.getOr<string>("ip", "localhost:1213");

    auto num = cmd.getOr<int>("n", 10000);
    auto ell = cmd.getOr("l", 128);

    auto iscmp = cmd.getOr<int>("c", 0);
    // vector<block> value(num);
    
    if(iscmp == 0) {
        vector<block> data(num, toBlock(0, 0));
        BitVector output(num);
        eq2<uint8_t> e(role, ip, 0, 0);
        e.run(data, output, ell);
        for (auto it = output.begin(); it != output.end(); it++) {
            cout << *it << endl;
        }
    } else if (iscmp == 1) {
        vector<block> data(num, toBlock(0, 10));
        if (role == Role::Receiver) {
            for (int i = 0; i < num; ++i) {
                data[i] = toBlock(0, (10 + i) % 16);
            }
        } else {
            for (int i = 0; i < num; ++i) {
                data[i] = toBlock(0, (11 - i) % 16);
            }
        }
        BitVector output(num);
        cmp1<uint8_t> c(role, ip, num, ell);
        c.run(data, output, ell);
        for (auto it = output.begin(); it != output.end(); it++) {
            cout << *it << endl;
        }
    }
    
    return 0;
}