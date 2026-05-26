#include "eq.h"
#include <cryptoTools/Common/block.h>
#include <vector>

PEqTSender::PEqTSender(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_)
    : num(num_), numThreads(numThreads_), noCompress(noCompress_), socket(socket_)
{
    sender = new RsPsiSender();
    sender->init(num, num, 40, oc::ZeroBlock, false, numThreads);

    auto type = oc::DefaultMultType;

    sender->setMultType(type);

    if (noCompress) {
        sender->mCompress = false;
        sender->mMaskSize = sizeof(block);
    }
}

void PEqTSender::eq(std::vector<block> &sendSet)
{
    coproto::sync_wait(sender->run(sendSet, *socket));
}

PEqTSender::~PEqTSender()
{
    delete sender;
}

PEqTRecver::PEqTRecver(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_)
    : num(num_), numThreads(numThreads_), noCompress(noCompress_), socket(socket_)
{
    recver = new RsPsiReceiver();
    recver->init(num, num, 40, oc::ZeroBlock, false, numThreads);

    auto type = oc::DefaultMultType;

    recver->setMultType(type);

    if (noCompress) {
        recver->mCompress = false;
        recver->mMaskSize = sizeof(block);
    }
}

void PEqTRecver::eq(std::vector<block> &recvSet, std::vector<u64> &intersection)
{
    coproto::sync_wait(recver->run(recvSet, *socket));
    intersection = recver->mIntersection;
}

PEqTRecver::~PEqTRecver()
{
    delete recver;
}