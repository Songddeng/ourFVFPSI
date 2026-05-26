#pragma once

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cstdint>
#include "secure-join/Prf/AltModPrfProto.h"

using namespace secJoin;

// so-OPRF with input \mathbb{F}_3 and output \mathbb{F}_2
class SoOPRFSender {
public:
    SoOPRFSender(uint64_t num_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_);
    ~SoOPRFSender();

    void setup();
    void OPRF(std::vector<oc::block> &y0);

    AltModPrf::KeyType getKey()
    {
        return sender->getKey();
    }

    uint64_t num;
    uint64_t numThreads;
    bool useOle;
    coproto::Socket *socket;
    PRNG *prng;

private:
    AltModWPrfSender *sender;
    macoro::thread_pool *pool;
    CorGenerator *ole;
};

class SoOPRFRecver {
public:
    SoOPRFRecver(uint64_t num_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_);
    ~SoOPRFRecver();

    void setup();
    void OPRF(std::vector<oc::block> &x, std::vector<oc::block> &y1);

    uint64_t num;
    uint64_t numThreads;
    bool useOle;
    coproto::Socket *socket;
    PRNG *prng;

private:
    AltModWPrfReceiver *recver;
    macoro::thread_pool *pool;
    CorGenerator *ole;
};
