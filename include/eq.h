#pragma once

#include <sys/types.h>
#include <vector>
#include "volePSI/RsPsi.h"

using namespace volePSI;

class PEqTSender {
public:
    PEqTSender(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_);
    ~PEqTSender();
    void eq(std::vector<block> &sendSet);

    uint64_t num;
    uint64_t numThreads;
    bool noCompress;

private:
    RsPsiSender *sender;
    coproto::Socket *socket;
};

class PEqTRecver {
public:
    PEqTRecver(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_);
    ~PEqTRecver();
    void eq(std::vector<block> &recvSet, std::vector<u64> &intersection);

    uint64_t num;
    uint64_t numThreads;
    bool noCompress;

private:
    RsPsiReceiver *recver;
    coproto::Socket *socket;
};