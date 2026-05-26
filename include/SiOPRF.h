#pragma once

#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cstdint>
#include "secure-join/Prf/AltModPrfProto.h"

using namespace secJoin;

class SiOPRFSender {
public:
    SiOPRFSender(
        uint64_t num_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_, coproto::Socket *socket2_, std::optional<AltModPrf::KeyType> key_ = {});
    ~SiOPRFSender();

    void setup();
    void OPRF(std::vector<oc::block> &x0, std::vector<oc::block> &y0);

    AltModPrf::KeyType getKey()
    {
        return sender->getKey();
    }

    uint64_t num;
    uint64_t numThreads;
    bool useOle;
    coproto::Socket *socket;
    coproto::Socket *socket2;
    PRNG *prng;

private:
    AltModWPrfSender *sender;
    macoro::thread_pool *pool;
    CorGenerator *ole;
};

class SiOPRFRecver {
public:
    SiOPRFRecver(
        uint64_t num_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_, coproto::Socket *socket2_, std::optional<AltModPrf::KeyType> key_ = {});
    ~SiOPRFRecver();

    void setup();
    void OPRF(std::vector<oc::block> &x1, std::vector<oc::block> &y1);

    uint64_t num;
    uint64_t numThreads;
    bool useOle;
    coproto::Socket *socket;
    coproto::Socket *socket2;
    PRNG *prng;

private:
    AltModWPrfReceiver *recver;
    macoro::thread_pool *pool;
    CorGenerator *ole;
};
