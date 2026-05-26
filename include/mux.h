#pragma once

#include <cryptoTools/Common/BitVector.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <vector>
#include <volePSI/Defines.h>

using namespace volePSI;
using namespace osuCrypto;

void ssPEQT(u32 idx, std::vector<block> &input, BitVector &out, Socket &chl, u32 numThreads);

class MuxSender {
public:
    MuxSender(uint64_t num_, coproto::Socket *socket_);
    ~MuxSender();
    BitVector mux(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0);

    BitVector muxA(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0);

    void mux(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0, u64 len);

    void muxA(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0, u64 len);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtSender *sender;
    osuCrypto::SilentOtExtReceiver *recver;
    osuCrypto::PRNG *prng;
};

class MuxRecver {
public:
    MuxRecver(uint64_t num_, coproto::Socket *socket_);
    ~MuxRecver();
    BitVector mux(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1);
    BitVector muxA(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1);

    void mux(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1, u64 len);
    void muxA(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1, u64 len);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtSender *sender;
    osuCrypto::SilentOtExtReceiver *recver;
    osuCrypto::PRNG *prng;
};
