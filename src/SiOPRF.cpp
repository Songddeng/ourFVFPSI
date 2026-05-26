#include "SiOPRF.h"
#include <algorithm>
#include <coproto/Common/macoro.h>
#include <coproto/Socket/AsioSocket.h>
#include <macoro/start_on.h>
#include "secure-join/Prf/AltModPrf.h"

SiOPRFSender::SiOPRFSender(
    uint64_t num_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_, coproto::Socket *socket2_, std::optional<AltModPrf::KeyType> key_)
    : num(num_), numThreads(numThreads_), useOle(useOle_), socket(socket_), socket2(socket2_)
{
    sender = new AltModWPrfSender();
    pool = new macoro::thread_pool();
    auto e = pool->make_work();
    pool->create_threads(numThreads);
    sender->mUseMod2F4Ot = !useOle;
    // socket[0]->setExecutor(*pool);
    // socket[1]->setExecutor(*pool);
    prng = new PRNG(oc::ZeroBlock);

    // AltModPrf::KeyType kk;

    ole = new CorGenerator();
    ole->init(socket->fork(), *prng, 0, 1, std::max(u64(1024), num << 9), 0);

    std::vector<oc::block> rk1(AltModPrf::KeySize);
    std::vector<std::array<oc::block, 2>> sk0(AltModPrf::KeySize);
    for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
        rk1[i] = oc::block(i, *oc::BitIterator((u8 *)&key_, i));
        sk0[i][0] = oc::block(i, 0);
        sk0[i][1] = oc::block(i, 1);
    }

    sender->init(num, *ole, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, key_, rk1, sk0);
}

void SiOPRFSender::setup()
{
    // Setup implementation (if needed)
}

void SiOPRFSender::OPRF(std::vector<oc::block> &x0, std::vector<oc::block> &y0)
{
    // coproto::sync_wait(socket[0]->send(std::string("hello from sender\n")) | macoro::start_on(*pool));
    auto r = coproto::sync_wait(coproto::when_all_ready(sender->evaluate(x0, y0, *socket, *prng), ole->start()));

    std::get<0>(r).result();
    std::get<1>(r).result();
}

SiOPRFSender::~SiOPRFSender()
{
    delete sender;
    delete prng;
    delete ole;
}

SiOPRFRecver::SiOPRFRecver(
    uint64_t num_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_, coproto::Socket *socket2_, std::optional<AltModPrf::KeyType> key_)
    : num(num_), numThreads(numThreads_), useOle(useOle_), socket(socket_), socket2(socket2_)
{
    recver = new AltModWPrfReceiver();
    pool = new macoro::thread_pool();
    auto e = pool->make_work();
    pool->create_threads(numThreads);
    recver->mUseMod2F4Ot = !useOle;
    // socket[0]->setExecutor(*pool);
    // socket[1]->setExecutor(*pool);
    prng = new PRNG(oc::OneBlock);

    // AltModPrf::KeyType kk;

    ole = new CorGenerator();
    ole->init(socket->fork(), *prng, 1, 1, std::max(u64(1024), num << 9), 0);

    std::vector<oc::block> rk0(AltModPrf::KeySize);
    std::vector<std::array<oc::block, 2>> sk1(AltModPrf::KeySize);
    for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
        sk1[i][0] = oc::block(i, 0);
        sk1[i][1] = oc::block(i, 1);
        rk0[i] = oc::block(i, *oc::BitIterator((u8 *)&key_, i));
    }

    recver->init(num, *ole, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, key_, sk1, rk0);
};

void SiOPRFRecver::setup()
{
    // Setup implementation (if needed)
}

void SiOPRFRecver::OPRF(std::vector<oc::block> &x1, std::vector<oc::block> &y1)
{
    // std::string str;
    // coproto::sync_wait(socket[0]->recvResize(str) | macoro::start_on(*pool));
    // std::cout << str << std::endl;
    auto r = coproto::sync_wait(coproto::when_all_ready(recver->evaluate(x1, y1, *socket, *prng), ole->start()));

    std::get<0>(r).result();
    std::get<1>(r).result();
}

SiOPRFRecver::~SiOPRFRecver()
{
    delete recver;
    delete prng;
    delete ole;
}