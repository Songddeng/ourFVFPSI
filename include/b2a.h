#pragma once
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstdint>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <sys/types.h>
#include <vector>

class B2aSender {
public:
    B2aSender(uint64_t num_, coproto::Socket *socket_);
    ~B2aSender();
    void b2a(std::vector<oc::block> &blk, std::vector<oc::u64> &val);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtSender *sender;
    osuCrypto::PRNG *prng;
};

class B2aRecver {
public:
    B2aRecver(uint64_t num_, coproto::Socket *socket_);
    ~B2aRecver();
    void b2a(std::vector<oc::block> &blk, std::vector<oc::u64> &val);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtReceiver *receiver;
    osuCrypto::PRNG *prng;
};