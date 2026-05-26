#include <array>
#include <coproto/Common/macoro.h>
#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/block.h>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <macoro/sync_wait.h>
#include <macoro/when_all.h>
#include <secure-join/Defines.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "SiOPRF.h"
#include "SoOPPRF.h"
#include "SoOPRF.h"
#include "b2a.h"
#include "common.h"
#include "cryptoTools/Common/CLP.h"
#include "eq.h"
#include "fpsi.h"
#include "fpsi_prefix.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "mul.h"
#include "mux.h"
#include "secure-join/Prf/AltModPrf.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "utils.h"

using namespace secJoin;

std::map<std::string, TimerStat> timers;

void AltModWPrf_proto_bench(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    u64 trials = cmd.getOr("trials", 1);
    bool nt = cmd.getOr("nt", 1);
    auto useOle = cmd.isSet("ole");

    oc::Timer timer;

    AltModWPrfSender sender;
    AltModWPrfReceiver recver;

    sender.mUseMod2F4Ot = !useOle;
    recver.mUseMod2F4Ot = !useOle;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<oc::block> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::LocalAsyncSocket::makePair();
    auto sock2 = coproto::LocalAsyncSocket::makePair();
    macoro::thread_pool pool0;
    auto e0 = pool0.make_work();
    pool0.create_threads(nt);
    macoro::thread_pool pool1;
    auto e1 = pool1.make_work();
    pool1.create_threads(nt);
    sock[0].setExecutor(pool0);
    sock[1].setExecutor(pool1);
    sock2[0].setExecutor(pool0);
    sock2[1].setExecutor(pool1);

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);

    AltModPrf dm;
    AltModPrf::KeyType kk;
    kk = prng0.get();
    dm.setKey(kk);
    // sender.setKey(kk);

    CorGenerator ole0, ole1;
    ole0.init(sock2[0].fork(), prng0, 0, nt, 1 << 18, cmd.getOr("mock", 1));
    ole1.init(sock2[1].fork(), prng1, 1, nt, 1 << 18, cmd.getOr("mock", 1));

    prng0.get(x.data(), x.size());
    std::vector<oc::block> rk(AltModPrf::KeySize);
    std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
    for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
        sk[i][0] = oc::block(i, 0);
        sk[i][1] = oc::block(i, 1);
        rk[i] = oc::block(i, *oc::BitIterator((u8 *)&sender.mKeyMultRecver.mKey, i));
    }
    sender.setKeyOts(kk, rk);
    recver.setKeyOts(sk);
    u64 numOle = 0;
    u64 numF4BitOt = 0;
    u64 numOt = 0;

    auto begin = timer.setTimePoint("begin");
    for (u64 t = 0; t < trials; ++t) {
        sender.init(n, ole0);
        recver.init(n, ole1);

        numOle += ole0.mGenState->mNumOle;
        numF4BitOt += ole0.mGenState->mNumF4BitOt;
        numOt += ole0.mGenState->mNumOt;

        auto r = coproto::sync_wait(coproto::when_all_ready(
            ole0.start() | macoro::start_on(pool0),
            ole1.start() | macoro::start_on(pool1),
            sender.evaluate({}, y0, sock[0], prng0) | macoro::start_on(pool0),
            recver.evaluate(x, y1, sock[1], prng1) | macoro::start_on(pool1)));
        std::get<0>(r).result();
        std::get<1>(r).result();
        std::get<2>(r).result();
        std::get<3>(r).result();
    }
    auto end = timer.setTimePoint("end");

    auto ntr = n * trials;

    std::cout << "AltModWPrf n:" << n << ", " << std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() / double(ntr) << "ns/eval "
              << sock[0].bytesSent() / double(ntr) << "+" << sock[0].bytesReceived() / double(ntr) << "="
              << (sock[0].bytesSent() + sock[0].bytesReceived()) / double(ntr) << " bytes/eval ";

    std::cout << numOle / double(ntr) << " ole/eval ";
    std::cout << numF4BitOt / double(ntr) << " f4/eval ";
    std::cout << numOt / double(ntr) << " ot/eval ";

    std::cout << std::endl;

    if (cmd.isSet("v")) {
        std::cout << timer << std::endl;
        std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
    }
}

auto sender(std::vector<block> &y0, CorGenerator &ole, AltModPrf &dm, AltModWPrfSender &s, coproto::Socket &sock, PRNG &prng)
{
    size_t n = y0.size();

    std::vector<oc::block> rk(AltModPrf::KeySize);
    for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
        rk[i] = oc::block(i, *oc::BitIterator((u8 *)&dm.mExpandedKey, i));
    }

    s.init(n, ole, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk);

    return s.evaluate({}, y0, sock, prng);
}

void AltModWPrf_proto_test(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1024);
    bool noCheck = cmd.isSet("nc");
    bool debug = cmd.isSet("debug");

    oc::Timer timer;

    AltModWPrfSender sender;
    AltModWPrfReceiver recver;
    sender.mDebug = debug;
    recver.mDebug = debug;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<oc::block> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::AsioSocket::makePair();

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);

    AltModPrf dm(prng0.get());

    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1, 1 << 18, cmd.getOr("mock", 1));
    ole1.init(sock[1].fork(), prng1, 1, 1, 1 << 18, cmd.getOr("mock", 1));

    prng0.get(x.data(), x.size());

    if (cmd.isSet("doKeyGen") == false) {
        std::vector<oc::block> rk(AltModPrf::KeySize);
        std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
        for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
            sk[i][0] = oc::block(i, 0);
            sk[i][1] = oc::block(i, 1);
            rk[i] = oc::block(i, *oc::BitIterator((u8 *)&dm.mExpandedKey, i));
        }
        sender.init(n, ole0, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk);
        recver.init(n, ole1, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);
    } else {
        sender.init(n, ole0);
        recver.init(n, ole1);
    }

    auto r = coproto::sync_wait(
        coproto::when_all_ready(sender.evaluate({}, y0, sock[0], prng0), recver.evaluate(x, y1, sock[1], prng1), ole0.start(), ole1.start()));

    std::get<0>(r).result();
    std::get<1>(r).result();
    std::get<2>(r).result();
    std::get<3>(r).result();

    if (cmd.isSet("v")) {
        std::cout << timer << std::endl;
        std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;
    }

    if (noCheck)
        return;

    AltModPrf prf(sender.getKey());
    std::vector<block> y(x.size());
    prf.eval(x, y);
    for (u64 ii = 0; ii < n; ++ii) {
        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y[ii]) {
            std::cout << "i   " << ii << std::endl;
            std::cout << "act " << yy << std::endl;
            std::cout << "exp " << y[ii] << std::endl;
            throw RTE_LOC;
        }
    }
}

int AltModWPrf_shared_test(const oc::CLP &cmd)
{
    oc::Timer timer;
    timer.setTimePoint("param");

    u64 n = 1 << 20;

    PRNG prng0(block(cmd.getOr("seed", 0), 0));
    PRNG prng1(block(cmd.getOr("seed", 0), 1));

    AltModWPrfSender sender;
    AltModWPrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<oc::block> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();

    AltModPrf dm_(prng0.get());
    AltModPrf::KeyType k = dm_.mExpandedKey;
    AltModPrf::KeyType k1 = prng0.get();
    AltModPrf::KeyType k0 = k1 ^ k;

    oc::AlignedUnVector<block> x0(n), x1(n);
    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1, 1 << 18, 0);
    ole1.init(sock[1].fork(), prng1, 1, 1, 1 << 18, 0);

    prng0.get(x.data(), x.size());
    prng0.get(x0.data(), x0.size());
    for (u64 i = 0; i < n; ++i) {
        x1[i] = x[i] ^ x0[i];
    }

    std::vector<oc::block> rk0(AltModPrf::KeySize), rk1(AltModPrf::KeySize);
    std::vector<std::array<oc::block, 2>> sk0(AltModPrf::KeySize), sk1(AltModPrf::KeySize);
    for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
        sk1[i][0] = oc::block(i, 0);
        sk1[i][1] = oc::block(i, 1);
        rk1[i] = oc::block(i, *oc::BitIterator((u8 *)&k1, i));
        sk0[i][0] = oc::block(i, 0);
        sk0[i][1] = oc::block(i, 1);
        rk0[i] = oc::block(i, *oc::BitIterator((u8 *)&k0, i));
    }

    sender.init(n, ole0, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, k1, rk1, sk0);

    recver.init(n, ole1, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, k0, sk1, rk0);

    Timer timer2;

    timer2.setTimePoint("begin");

    std::thread th_sender([&] {
        auto r = coproto::sync_wait(coproto::when_all_ready(sender.evaluate(x0, y0, sock[0], prng0), ole0.start()));
        std::get<0>(r).result();
        std::get<1>(r).result();
    });

    std::thread th_recver([&] {
        auto r = coproto::sync_wait(coproto::when_all_ready(recver.evaluate(x1, y1, sock[1], prng1), ole1.start()));
        std::get<0>(r).result();
        std::get<1>(r).result();
    });

    th_sender.join();
    th_recver.join();

    timer2.setTimePoint("begin");

    std::cout << timer2 << std::endl;

    // std::cout << sock[0].bytesReceived() / 1000.0 << " " << sock[0].bytesSent() / 1000.0 << " kB " << std::endl;

    std::vector<block> y(x.size());
    dm_.eval(x, y);
    for (u64 ii = 0; ii < n; ++ii) {
        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y[ii]) {
            // std::cout << "i   " << ii << std::endl;
            // std::cout << "act " << yy << std::endl;
            // std::cout << "exp " << y[ii] << std::endl;
            // throw RTE_LOC;
            return 0;
        }
    }
    return 1;
}

int AltModWPrf_sharedKey_test(const oc::CLP &cmd)
{
    oc::Timer timer;
    timer.setTimePoint("param");

    u64 n = cmd.getOr("n", (1ull << 7) + 123);

    PRNG prng0(block(cmd.getOr("seed", 0), 0));
    PRNG prng1(block(cmd.getOr("seed", 0), 1));

    AltModWPrfSender sender;
    AltModWPrfReceiver recver;

    sender.setTimer(timer);
    recver.setTimer(timer);

    std::vector<oc::block> x(n);
    std::vector<oc::block> y0(n), y1(n);

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();

    AltModPrf dm_(prng0.get());
    AltModPrf::KeyType k = dm_.mExpandedKey;
    AltModPrf::KeyType k1 = prng0.get();
    AltModPrf::KeyType k0 = k1 ^ k;

    oc::AlignedUnVector<block> x0(n), x1(n);
    CorGenerator ole0, ole1;
    ole0.init(std::move(sock2[0]), prng0, 0, 1, 1 << 18, cmd.getOr("mock", 1));
    ole1.init(std::move(sock2[1]), prng1, 1, 1, 1 << 18, cmd.getOr("mock", 1));

    prng0.get(x.data(), x.size());
    prng0.get(x0.data(), x0.size());
    for (u64 i = 0; i < n; ++i) {
        // if (i & 1)
        //{
        //	x1[i] = { 0ull, 0ull };
        //	x0[i] = x[i];
        // }
        // else
        //{
        //	x0[i] = { 0ull, 0ull };
        //	x1[i] = x[i];
        // }

        // auto mask = prng0.get<block>();
        // x0[i] = x[i] & mask; //{ 0ull, 0ull };
        // x1[i] = x[i] & (~mask);//^ x0[i];

        x1[i] = x[i] ^ x0[i];

        // if (i < 10)
        //	std::cout << "x[" << i << "] " << x[i] << std::endl;

        if (x[i] != (x0[i] ^ x1[i]))
            throw RTE_LOC;
    }
    timer.setTimePoint("pre");

    if (cmd.isSet("doKeyGen") == false) { // note: should be base OT
        std::vector<oc::block> rk0(AltModPrf::KeySize), rk1(AltModPrf::KeySize);
        std::vector<std::array<oc::block, 2>> sk0(AltModPrf::KeySize), sk1(AltModPrf::KeySize);
        for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
            sk1[i][0] = oc::block(i, 0);
            sk1[i][1] = oc::block(i, 1);
            rk1[i] = oc::block(i, *oc::BitIterator((u8 *)&k1, i));
            sk0[i][0] = oc::block(i, 0);
            sk0[i][1] = oc::block(i, 1);
            rk0[i] = oc::block(i, *oc::BitIterator((u8 *)&k0, i));
        }
        timer.setTimePoint("in0");

        sender.init(n, ole0, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, k1, rk1, sk0);
        timer.setTimePoint("in1");
        recver.init(n, ole1, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, k0, sk1, rk0);
    } else {
        sender.init(n, ole0, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, k1);
        recver.init(n, ole1, AltModPrfKeyMode::Shared, AltModPrfInputMode::Shared, k0);
    }
    timer.setTimePoint("init");

    // auto r = coproto::sync_wait(
    //     coproto::when_all_ready(sender.evaluate(x0, y0, sock[0], prng0), recver.evaluate(x1, y1, sock[1], prng1), ole0.start(), ole1.start()));
    // timer.setTimePoint("run");

    // std::get<0>(r).result();
    // std::get<1>(r).result();
    // std::get<2>(r).result();
    // std::get<3>(r).result();

    std::thread th_sender([&] {
        auto r = coproto::sync_wait(coproto::when_all_ready(sender.evaluate(x0, y0, sock[0], prng0), ole0.start()));
        std::get<0>(r).result();
        std::get<1>(r).result();
    });

    std::thread th_recver([&] {
        auto r = coproto::sync_wait(coproto::when_all_ready(recver.evaluate(x1, y1, sock[1], prng1), ole1.start()));
        std::get<0>(r).result();
        std::get<1>(r).result();
    });

    th_sender.join();
    th_recver.join();

    std::vector<block> y(x.size());
    dm_.eval(x, y);
    for (u64 ii = 0; ii < n; ++ii) {
        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y[ii]) {
            std::cout << "i   " << ii << std::endl;
            std::cout << "act " << yy << std::endl;
            std::cout << "exp " << y[ii] << std::endl;
            return 0;
        }
    }
    return 1;
}

void simulation_2pc()
{
    u64 n = 1024;
    bool debug = false, doKeyGen = false, verbose = true, noCheck = false;
    int mock = 1;

    AltModWPrfSender sender;
    AltModWPrfReceiver recver;
    sender.mDebug = recver.mDebug = debug;

    oc::Timer timer;
    sender.setTimer(timer);
    recver.setTimer(timer);

    // 两端 socket（同进程内但走 TCP 栈）
    auto pair = coproto::AsioSocket::makePair();

    PRNG prng0(oc::ZeroBlock), prng1(oc::OneBlock);

    // 公共 key 准备（可按你的分工调整）
    AltModPrf dm(prng0.get());
    std::vector<oc::block> rk(AltModPrf::KeySize);
    std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
    for (u64 i = 0; i < AltModPrf::KeySize; ++i) {
        sk[i][0] = oc::block(i, 0);
        sk[i][1] = oc::block(i, 1);
        rk[i] = oc::block(i, *oc::BitIterator((u8 *)&dm.mExpandedKey, i));
    }

    std::vector<oc::block> x(n), y0(n), y1(n);
    prng0.get(x.data(), x.size());

    CorGenerator ole0, ole1;

    std::thread th_sender([&] {
        ole0.init(pair[0].fork(), prng0, 0, 1, 1 << 18, mock);
        if (!doKeyGen)
            sender.init(n, ole0, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk);
        else
            sender.init(n, ole0);

        auto all = when_all_ready(sender.evaluate({}, y0, pair[0], prng0), ole0.start());
        auto r = sync_wait(std::move(all));
        std::get<0>(r).result();
        std::get<1>(r).result();
    });

    std::thread th_receiver([&] {
        ole1.init(pair[1].fork(), prng1, 1, 1, 1 << 18, mock);
        if (!doKeyGen)
            recver.init(n, ole1, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);
        else
            recver.init(n, ole1);

        auto all = when_all_ready(recver.evaluate(x, y1, pair[1], prng1), ole1.start());
        auto r = sync_wait(std::move(all));
        std::get<0>(r).result();
        std::get<1>(r).result();
    });

    th_sender.join();
    th_receiver.join();

    if (verbose) {
        std::cout << timer << "\n";
        std::cout << pair[0].bytesReceived() / 1000.0 << " " << pair[0].bytesSent() / 1000.0 << " kB\n";
    }

    if (!noCheck) {
        AltModPrf prf(sender.getKey());
        std::vector<oc::block> y(n);
        prf.eval(x, y);
        for (u64 i = 0; i < n; ++i) {
            if ((y0[i] ^ y1[i]) != y[i])
                throw RTE_LOC;
        }
        if (verbose)
            std::cout << "check pass\n";
    }
}

// void sim_okvr()
// {
//     u64 n = 1 << 11;
//     std::vector<block> key(n), val(n);

//     auto decode_size = 10;
//     auto numQuery = 3 * decode_size;

//     std::vector<block> decode_val(decode_size);
//     std::vector<block> decode_key(decode_size);

//     PRNG prng(ZeroBlock);
//     prng.get<block>(key);
//     prng.get<block>(val);

//     memcpy(decode_key.data(), key.data(), decode_size * sizeof(block));

//     // offline phase

//     OkvrSender sender(key, val, n, numQuery);
//     OkvrReceiver receiver(decode_key, n, numQuery);

//     auto seal_key = receiver.save_keys();

//     sender.set_keys(seal_key);

//     // online phase

//     start_timer("online");

//     auto [hashs, idxs] = receiver.genIndex(decode_key);

//     auto [query, batch_query_index] = receiver.genQuery(idxs);

//     auto response = sender.genResponse(query);

//     auto densePart = sender.getDensePart();
//     auto sparsePart = sender.getSparsePart();

//     auto okvs = receiver.okvs;

//     std::vector<block> values(hashs.size());

//     vector<std::map<u64, block>> pp(okvs->binNum, std::map<u64, block>());

//     for (u64 i = 0; i < okvs->binNum; i++) {
//         for (u64 j = 0; j < okvs->denseSize; j++) {
//             pp[i][okvs->sparseSize + j] = densePart[i * okvs->denseSize + j];
//         }
//     }
//     for (u64 i = 0; i < idxs.size(); i++) {
//         for (u64 j = 0; j < 3; j++) {
//             pp[idxs[i][3]][idxs[i][j]] = sparsePart[idxs[i][3] * okvs->sparseSize + idxs[i][j]];
//             std::cout << sparsePart[idxs[i][3] * okvs->sparseSize + idxs[i][j]] << std::endl;
//         }
//     }
//     std::cout << "---------------------------------" << std::endl;
//     okvs->decode(hashs, idxs, values, pp, 0);

//     // auto as = receiver.client->extract_batch_answer(response);

//     // test_batch_pir_correctness(*sender.server, as, batch_query_index, *receiver.pir_parms);

//     receiver.decode(response, batch_query_index, hashs, idxs, densePart);

//     stop_timer("online");

//     print_all_timers("");

//     memcmp(values.data(), val.data(), decode_size * sizeof(block)) == 0 ? std::cout << "ok\n" : std::cout << "error\n";
// }

void SoOPRF_test()
{
    auto sock0 = coproto::AsioSocket::makePair();

    SoOPRFSender sender(1 << 20, 1, false, &sock0[0]);
    SoOPRFRecver recver(1 << 20, 1, false, &sock0[1]);

    sender.setup();
    recver.setup();

    PRNG prng(oc::ZeroBlock);
    std::vector<oc::block> x(1 << 20);
    std::vector<oc::block> y0(1 << 20), y1(1 << 20);
    prng.get(x.data(), x.size());

    Timer timer;
    timer.setTimePoint("begin");

    std::thread thread_sender([&] { sender.OPRF(y0); });

    std::thread thread_recver([&] { recver.OPRF(x, y1); });

    thread_sender.join();
    thread_recver.join();

    timer.setTimePoint("end");

    std::cout << timer << std::endl;

    std::cout << sender.getKey() << std::endl;

    AltModPrf prf(sender.getKey());
    std::vector<block> y(x.size());
    prf.eval(x, y);
    for (u64 ii = 0; ii < x.size(); ++ii) {
        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y[ii]) {
            std::cout << "i   " << ii << std::endl;
            std::cout << "act " << yy << std::endl;
            std::cout << "exp " << y[ii] << std::endl;
            throw RTE_LOC;
        }
    }

    std::cout << "All Pass!" << std::endl;
}

void SoOPPRF_test()
{
    auto sock0 = coproto::AsioSocket::makePair();

    SoOPPRFSender sender(1 << 20, 1 << 20, 1, false, &sock0[0]);
    SoOPPRFRecver recver(1 << 20, 1 << 20, 1, false, &sock0[1]);

    PRNG prng(sysRandomSeed());
    std::vector<oc::block> keys0(1 << 20);
    std::vector<oc::block> vals0(1 << 20);
    std::vector<oc::block> keys1(1 << 20);
    std::vector<oc::block> y0(1 << 20), y1(1 << 20);

    prng.get<oc::block>(keys0);
    prng.get<oc::block>(vals0);
    memcpy(keys1.data(), keys0.data(), (1 << 20) * sizeof(block));

    std::thread thread_sender([&] { sender.OPPRF(keys0, vals0, y0); });

    std::thread thread_recver([&] { recver.OPPRF(keys1, y1); });

    thread_sender.join();
    thread_recver.join();

    for (int i = 0; i < (1 << 20); i++) {
        if ((y0[i] ^ y1[i]) != vals0[i]) {
            std::cout << "i   " << i << std::endl;
            std::cout << "act " << (y0[i] ^ y1[i]) << std::endl;
            std::cout << "exp " << vals0[i] << std::endl;
            throw RTE_LOC;
        }
    }

    std::cout << "All Pass!" << std::endl;
}

void SiOPRF_test()
{
    size_t n = 1 << 10;

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();

    PRNG prng(oc::ZeroBlock);
    std::vector<oc::block> x(n), x0(n), x1(n);
    std::vector<oc::block> y0(n), y1(n);

    AltModPrf dm(prng.get());

    AltModPrf::KeyType k = dm.mExpandedKey;
    AltModPrf::KeyType k1 = prng.get();
    AltModPrf::KeyType k0 = k1 ^ k;

    prng.get(x.data(), x.size());
    prng.get(x0.data(), x0.size());

    for (u64 i = 0; i < n; ++i) {
        x1[i] = x[i] ^ x0[i];
    }

    // sender.setup();
    // recver.setup();

    std::thread thread_sender([&] {
        SiOPRFSender sender(1 << 10, 1, false, &sock[0], &sock2[0], k0);
        sender.OPRF(x0, y0);
    });

    std::thread thread_recver([&] {
        SiOPRFRecver recver(1 << 10, 1, false, &sock[1], &sock2[1], k1);
        recver.OPRF(x1, y1);
    });

    thread_sender.join();
    thread_recver.join();

    std::vector<block> y(x.size());
    dm.eval(x, y);
    for (u64 ii = 0; ii < x.size(); ++ii) {
        auto yy = (y0[ii] ^ y1[ii]);
        if (yy != y[ii]) {
            std::cout << "i   " << ii << std::endl;
            std::cout << "act " << yy << std::endl;
            std::cout << "exp " << y[ii] << std::endl;
            throw RTE_LOC;
        }
    }

    std::cout << "All Pass!" << std::endl;
}

void eq_test()
{
    auto sock = coproto::AsioSocket::makePair();

    PEqTSender sender(1 << 10, 1, false, &sock[0]);
    PEqTRecver recver(1 << 10, 1, false, &sock[1]);

    PRNG prng(oc::ZeroBlock);
    std::vector<oc::block> sendSet(1 << 10);
    std::vector<oc::block> recvSet(1 << 10);
    prng.get(sendSet.data(), sendSet.size());
    prng.get(recvSet.data(), recvSet.size());

    for (int i = 0; i < 10; i++) {
        recvSet[i] = sendSet[i];
    }

    std::vector<u64> intersection;

    std::thread thread_sender([&] { sender.eq(sendSet); });

    std::thread thread_recver([&] { recver.eq(recvSet, intersection); });

    thread_sender.join();
    thread_recver.join();

    for (auto e : intersection) {
        cout << e << " ";
    }
    std::cout << std::endl;

    std::cout << "All Pass!" << std::endl;
}

void mul_test()
{
    auto sock = coproto::LocalAsyncSocket::makePair();

    int n = 1 << 20;

    MulSender sender(n, &sock[0]);
    MulRecver recver(n, &sock[1]);
    std::vector<u64> blk(n);
    std::vector<u64> input0(n);
    std::vector<u64> input1(n);

    PRNG prng(oc::sysRandomSeed());

    for (int i = 0; i < n; i++) {
        // blk[i] = prng.get<u64>();
        input0[i] = prng.get<u64>();
        input1[i] = prng.get<u64>();
    }

    std::vector<u64> val0(n);
    std::vector<u64> val1(n);

    osuCrypto::Timer timer;
    timer.setTimePoint("begin");

    std::thread thread_sender([&] { sender.mul(input0, val0); });

    std::thread thread_recver([&] { recver.mul(input1, val1); });

    thread_sender.join();
    thread_recver.join();

    timer.setTimePoint("proto end");

    for (int i = 0; i < 1; i++) {
        if (val0[i] + val1[i] != input0[i] * input1[i]) {
            std::cout << "error at " << i << std::endl;
            std::cout << val0[i] + val1[i] << " " << input0[i] * input1[i] << std::endl;
        }
    }

    std::cout << (sock[0].bytesSent() + sock[0].bytesReceived()) * 8.0 / n << std::endl;
    std::cout << timer << std::endl;
}

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv);

    // AltModWPrf_proto_bench(cmd);

    // AltModWPrf_proto_test(cmd);

    // AltModWPrf_shared_test(cmd);

    // simulation_2pc();

    // sim_okvr();

    // SoOPRF_test();

    // AltModWPrf_proto_bench(cmd);

    // SoOPPRF_test();

    // SiOPRF_test();

    // int cnt = 0;

    // for (int i = 0; i < 1; i++) {
    //     if (AltModWPrf_shared_test(cmd))
    //         cnt++;
    // }

    // std::cout << "pass rate: " << cnt / 10000.0 << std::endl;

    // eq_test();

    int lp = cmd.getOr("p", 0);

    if (lp != 0) {
        if (cmd.isSet("prefix")) {
            fuzzyPsiLpPrefix(cmd);
        } else {
            fuzzyPsiLp(cmd);
        }
    } else {
        if (cmd.isSet("prefix")) {
            fuzzyPsiPrefix(cmd);
        } else {
            fuzzyPsi(cmd);
        }
    }

    return 0;
}