#include "fpsi.h"
#include <cmath>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cstdlib>
#include <fmt/format.h>
#include <iostream>
#include <limits>
#include <macoro/trace.h>
#include <macoro/sync_wait.h>
#include <macoro/thread_pool.h>
#include <macoro/when_all.h>
#include <thread>
#include <vector>
#include "OKVS.h"
#include "SiOPRF.h"
#include "SoOPPRF.h"
#include "b2a.h"
#include "eq.h"
#include "stage_profile.h"
#include "secure-join/Prf/AltModPrf.h"
#include "utils.h"

using namespace secJoin;

namespace {

uint64_t totalCommBytes(std::array<coproto::AsioSocket, 2> &sock, std::array<coproto::AsioSocket, 2> &sock2)
{
    return sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent();
}

u64 gridIndex(u64 value, int delta)
{
    if (delta <= 0) {
        throw std::runtime_error("delta must be positive");
    }

    return value / static_cast<u64>(delta);
}

std::pair<u64, u64> gridCandidateRange(u64 value, int delta)
{
    const auto idx = gridIndex(value, delta);
    const auto start = idx == 0 ? 0 : idx - 1;
    const auto end = idx == std::numeric_limits<u64>::max() ? idx : idx + 1;

    return { start, end };
}

void printSummaryLine(
    const std::string &proto,
    const std::string &metric,
    size_t d,
    int delta,
    u64 n,
    double comm,
    double comp,
    double fmapComm,
    double filterComm,
    double otComm)
{
    std::cout << fmt::format(
                     "{:<12} {:<6} {:^5} {:^5} {:^5} {:^10.3f} {:^10.3f} {:^10.3f} {:^10.3f} {:^10.3f}",
                     proto,
                     metric,
                     d,
                     delta,
                     n,
                     comm,
                     comp,
                     fmapComm,
                     filterComm,
                     otComm)
              << std::endl;
}

} // namespace

// to be fixed
void LocalMap(std::vector<std::vector<u64>> &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta)
{
    PRNG prng(ZeroBlock);

    u64 m = inputs.size();
    u64 d = inputs[0].size();

    pid.resize(m);

    std::vector<std::vector<std::pair<u64, u64>>> intervals(d);

    std::vector<block> randR(m * d);
    prng.get<block>(randR.data(), randR.size());

    u64 maxInter = 0;

    // Merge overlapping intervals
    for (u64 i = 0; i < d; i++) {
        std::vector<std::pair<u64, u64>> interval;
        interval.reserve(m);

        // Encode only the grid cells that can collide with values within delta.
        for (auto &elem : inputs) {
            interval.push_back(gridCandidateRange(elem[i], delta));
        }

        // Sort points by x-coordinate; if equal, sort by y-coordinate
        std::sort(interval.begin(), interval.end());

        for (auto [start, end] : interval) {
            // If intervals overlap, merge them
            // If no overlap, add the new interval
            if (!intervals[i].empty() && start <= intervals[i].back().second) {
                intervals[i].back().second = max(intervals[i].back().second, end);
            } else {
                intervals[i].emplace_back(start, end);
            }
            maxInter = max(intervals[i].back().second - intervals[i].back().first, maxInter);
        }
        // std::cout << "Dimension " << i << " : total intervals = " << intervals[i].size() << std::endl;
    }

    // gen Local ID

    auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
        return a.second < value; // Find the first interval where value <= interval.second
    };

    for (u64 i = 0; i < d; i++) {
        for (u64 j = 0; j < m; j++) {
            auto elem = inputs[j];
            auto idx = gridIndex(elem[i], delta);

            auto it = std::lower_bound(intervals[i].begin(), intervals[i].end(), idx, compare_lambda);

            if (it != intervals[i].end() && it->first <= idx && idx <= it->second) {
                auto interval_index = distance(intervals[i].begin(), it);
                pid[j] ^= randR[i * m + interval_index];
            } else {
                std::cout << i << " " << elem[i] << std::endl;
                throw runtime_error("recv getID random error");
            }
        }
    }

    for (u64 i = 0; i < d; i++) {
        for (u64 j = 0; j < intervals[i].size(); j++) {
            auto [start, end] = intervals[i][j];
            for (u64 k = start; k <= end; k++) {
                block key = block(i, k);
                block val = randR[i * m + j];
                listKey.push_back(key);
                listVal.push_back(val);
            }
        }
    }

    if (listKey.size() > d * m * 3) {
        throw runtime_error("something wrong in LocalMap");
    }
    while (listKey.size() < d * m * 3) {
        listKey.push_back(prng.get<block>());
        listVal.push_back(prng.get<block>());
    }
    Hash(listKey);
}

void FuzzyMap(
    u64 n,
    size_t d,
    int delta,
    std::vector<std::vector<u64>> &sendSet,
    std::vector<block> &sendPid,
    std::vector<block> &senderOKVS,
    std::vector<std::vector<u64>> &recvSet,
    std::vector<block> &recvPid,
    std::vector<block> &recverOKVS,
    std::vector<block> &ID_R,
    std::vector<block> &ID_S,
    AltModPrf::KeyType &k0,
    AltModPrf::KeyType &k1,
    std::array<coproto::AsioSocket, 2> &sock,
    std::array<coproto::AsioSocket, 2> &sock2,
    oc::Timer &time)
{
    std::vector<block> rand_R_j(n);
    std::vector<block> rand_S_j(n);

    std::thread sendSoOPPRFReverse([&] {
        SoOPPRFRecver recv(n * d, n * d * 3, 1, false, &sock[0]);

        std::vector<block> inputs(n * d);
        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                inputs[i * d + j] = block(j, gridIndex(sendSet[i][j], delta));
            }
        }
        std::vector<block> rand_S(n * d);

        Hash(inputs);
        recv.OPPRF(inputs, rand_S);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_S_j[i] ^= rand_S[i * d + j];
            }
            rand_S_j[i] = rand_S_j[i] ^ sendPid[i];
        }
    });

    std::thread recvSoOPPRFReverse([&] {
        SoOPPRFSender send(n * d, n * d * 3, 1, false, &sock[1]);

        std::vector<block> rand_R(n * d);

        // send.OPPRF(recvListKey, recvListVal, rand_R);
        send.OPPRF(recverOKVS, rand_R);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_R_j[i] ^= rand_R[i * d + j];
            }
        }
    });

    sendSoOPPRFReverse.join();
    recvSoOPPRFReverse.join();

    time.setTimePoint("soOPRF Reverse done");

    std::thread sendSiOPRFReverse([&] {
        SiOPRFRecver siRecv(n, 1, false, &sock[0], &sock2[0], k0);

        std::vector<block> share_S(n);

        siRecv.OPRF(rand_S_j, share_S);

        std::vector<block> share_R(n);

        coproto::sync_wait(sock[0].recv(share_R));

        for (int i = 0; i < n; i++) {
            ID_S[i] = share_R[i] ^ share_S[i];
        }
    });

    std::thread recvSiOPRFReverse([&] {
        SiOPRFSender siSend(n, 1, false, &sock[1], &sock2[1], k1);

        std::vector<block> share_R(n);

        siSend.OPRF(rand_R_j, share_R);

        coproto::sync_wait(sock[1].send(share_R));
    });

    sendSiOPRFReverse.join();
    recvSiOPRFReverse.join();

    time.setTimePoint("siOPRF Reverse done");

    rand_R_j = std::vector<block>(n, ZeroBlock);
    rand_S_j = std::vector<block>(n, ZeroBlock);

    std::thread sendSoOPPRF([&] {
        SoOPPRFSender send(n * d, n * d * 3, 1, false, &sock[0]);

        std::vector<block> rand_S(n * d);

        // send.OPPRF(sendListKey, sendListVal, rand_S);
        send.OPPRF(senderOKVS, rand_S);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_S_j[i] ^= rand_S[i * d + j];
            }
        }
    });

    std::thread recvSoOPPRF([&] {
        SoOPPRFRecver recv(n * d, n * d * 3, 1, false, &sock[1]);

        std::vector<block> inputs(n * d);
        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                inputs[i * d + j] = block(j, gridIndex(recvSet[i][j], delta));
            }
        }
        std::vector<block> rand_R(n * d);

        Hash(inputs);
        recv.OPPRF(inputs, rand_R);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_R_j[i] ^= rand_R[i * d + j];
            }
            rand_R_j[i] = rand_R_j[i] ^ recvPid[i];
        }
    });

    sendSoOPPRF.join();
    recvSoOPPRF.join();

    time.setTimePoint("soOPRF done");

    std::thread sendSiOPRF([&] {
        SiOPRFSender siSend(n, 1, false, &sock[0], &sock2[0], k0);

        std::vector<block> share_S(n);

        siSend.OPRF(rand_S_j, share_S);

        coproto::sync_wait(sock[0].send(share_S));
    });

    std::thread recvSiOPRF([&] {
        SiOPRFRecver siRecv(n, 1, false, &sock[1], &sock2[1], k1);

        std::vector<block> share_R(n);

        siRecv.OPRF(rand_R_j, share_R);

        std::vector<block> share_S(n);

        coproto::sync_wait(sock[1].recv(share_S));

        for (int i = 0; i < n; i++) {
            ID_R[i] = share_R[i] ^ share_S[i];
        }
    });

    sendSiOPRF.join();
    recvSiOPRF.join();

    time.setTimePoint("siOPRF done");
}

void fuzzyPsi(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int interSize = cmd.getOr("nn", 4);

    std::vector<std::vector<u64>> sendSet;
    std::vector<block> sendPid;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;

    PRNG prng(sysRandomSeed());

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        sendSet.push_back(tmp);
    }

    std::vector<std::vector<u64>> recvSet;
    std::vector<block> recvPid;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        recvSet.push_back(tmp);
    }

    std::vector<u64> interIndices;
    while (interIndices.size() < interSize) {
        u64 idx = prng.get<u64>() % n;
        if (std::find(interIndices.begin(), interIndices.end(), idx) == interIndices.end()) {
            interIndices.push_back(idx);
        }
    }

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (delta + 1));
        }
    }

    std::thread sendLocalMap([&] { LocalMap(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMap(recvSet, recvPid, recvListKey, recvListVal, delta); });

    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(n * d * 3);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey);
    // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    std::vector<block> senderPrfVals(sendListKey.size());
    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(sendListKey, senderPrfVals);
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); i++) {
        sendListVal[i] = sendListVal[i] ^ senderPrfVals[i];
        recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    }

    auto senderOKVS = preOKVS.encode(sendListKey, sendListVal);
    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto s = time.setTimePoint("offline preprocess OKVS done");

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();
    StageProfileSummary stageSummary;

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        StageProfileRun stageRun(stageSummary);
        stageRun.start(totalCommBytes(sock, sock2));

        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);
        std::vector<block> rand_R_j(n);
        std::vector<block> rand_S_j(n);

        AltModPrf RO(prng.get());
        auto key = RO.mExpandedKey;
        AltModPrf::KeyType k1 = prng.get();
        AltModPrf::KeyType k0 = k1 ^ key;

        FuzzyMap(n, d, delta, sendSet, sendPid, senderOKVS, recvSet, recvPid, recverOKVS, ID_R, ID_S, k0, k1, sock, sock2, time);

        // for (u64 i = 0; i < n; i++) {
        //     std::cout << "Sender ID: " << ID_S[i] << " Receiver ID: " << ID_R[i] << " " << i << std::endl;
        // }

        // fmap finish
        time.setTimePoint("fmap done");
        stageRun.mark("fmap done", totalCommBytes(sock, sock2));
        // std::cout << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB " <<
        // std::endl;

        std::vector<u8> choiceBit(n, 0);

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    inputs[i * d + j] = block(high(ID_S[i]) << 8, 0) ^ block(j, sendSet[i][j]); // 8 bits for dimension
                }
            }

            SoOPPRFRecver recv(n * d, n * d * (2 * delta + 1), 1, false, &sock[0]);

            std::vector<block> rand_S(n * d);

            recv.OPPRF(inputs, rand_S);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_S_j[i] ^= rand_S[i * d + j];
                }
            }

            PEqTSender eqSend(n, 1, false, &sock[0]);

            eqSend.eq(rand_S_j);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey(n * d * (2 * delta + 1));
            std::vector<block> filterVal(n * d * (2 * delta + 1));
            u64 idx = 0;

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    for (int t = -delta; t <= delta; t++) {
                        block key = block(high(ID_R[i]) << 8, 0) ^ block(j, recvSet[i][j] + t);
                        block val = ZeroBlock;
                        filterKey[idx] = key;
                        filterVal[idx] = val;
                        idx++;
                    }
                }
            }

            SoOPPRFSender send(n * d, n * d * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> rand_R(n * d);

            send.OPPRF(filterKey, filterVal, rand_R);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_R_j[i] ^= rand_R[i * d + j];
                }
            }

            PEqTRecver eqRecv(n, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(rand_R_j, intersection);

            for (auto &v : intersection) {
                choiceBit[v] = 1;
            }
        });

        sendFilter.join();
        recvFilter.join();

        time.setTimePoint("filter done");
        stageRun.mark("filter done", totalCommBytes(sock, sock2));
        // std::cout << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB " <<
        // std::endl;

        std::thread sendOT([&] {
            SilentOtExtSender send;
            send.configure(n, 128);
            send.mMultType = type;

            coproto::sync_wait(send.genSilentBaseOts(prng, sock[0]));

            std::vector<std::array<block, 2>> messages(n);

            coproto::sync_wait(send.send(messages, prng, sock[0]));

            std::vector<block> correctMessages(n * d / 2 * 2);
            PRNG prng0, prng1;
            for (int i = 0; i < n; i++) {
                prng0.SetSeed(messages[i][0]);
                prng1.SetSeed(messages[i][1]);
                for (int j = 0; j < d / 2; j++) {
                    correctMessages[i * d + j * 2] = prng0.get<block>();
                    correctMessages[i * d + j * 2 + 1] = block(sendSet[i][j * 2], sendSet[i][j * 2 + 1]) ^ prng0.get<block>();
                }
            }
            coproto::sync_wait(sock[0].send(correctMessages));
        });

        std::vector<std::vector<block>> matches;

        std::thread recvOT([&] {
            SilentOtExtReceiver recv;
            recv.configure(n, 128);
            recv.mMultType = type;

            coproto::sync_wait(recv.genSilentBaseOts(prng, sock[1]));

            std::vector<block> messages(n);
            BitVector choices(choiceBit.data(), choiceBit.size());

            coproto::sync_wait(recv.receive(choices, messages, prng, sock[1]));

            std::vector<block> correctMessages(n * d / 2 * 2);
            coproto::sync_wait(sock[1].recv(correctMessages));

            PRNG prng;
            for (int i = 0; i < n; i++) {
                if (choiceBit[i]) {
                    prng.SetSeed(messages[i]);
                    std::vector<block> element;
                    for (int j = 0; j < d / 2; j++) {
                        block val = prng.get<block>() ^ correctMessages[i * d + j * 2 + 1];
                        element.push_back(val);
                    }
                    matches.push_back(element);
                }
            }
        });

        sendOT.join();
        recvOT.join();
        stageRun.mark("OT done", totalCommBytes(sock, sock2));

        if (verbose) {
            for (int i = 0; i < choiceBit.size(); i++) {
                if (choiceBit[i]) {
                    std::cout << "intersection at index " << i << std::endl;
                }
                if (choiceBit[i] && std::find(interIndices.begin(), interIndices.end(), i) == interIndices.end()) {
                    throw runtime_error("false positive in fuzzyPsi");
                }
            }
            std::cout << "All matches found!" << std::endl;

            std::cout << time << std::endl;
            stageSummary.print();
        }
    }

    auto e = time.setTimePoint("OT done");

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;
    const double fmapComm = stageSummary.getAverageCommMB("fmap done");
    const double filterComm = stageSummary.getAverageCommMB("filter done");
    const double otComm = stageSummary.getAverageCommMB("OT done");

    printSummaryLine("[ours]", "L0", d, delta, n, comm, comp, fmapComm, filterComm, otComm);
    // std::cout << "comm: " << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB, "
    //   << " time: " << std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000) << " s" << std::endl;
}

void fuzzyPsiLp(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int lp = cmd.getOr("p", 2);
    int interSize = cmd.getOr("nn", 4);
    int verbose = cmd.getOr("v", 0);
    int numTry = cmd.getOr("try", 1);

    u64 delta_p = std::pow(delta, lp);
    int prefixLen = static_cast<int>(std::ceil(std::log2(delta_p + 1)));

    std::vector<std::vector<u64>> sendSet;
    std::vector<block> sendPid;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;

    PRNG prng(sysRandomSeed());

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        sendSet.push_back(tmp);
    }

    std::vector<std::vector<u64>> recvSet;
    std::vector<block> recvPid;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        recvSet.push_back(tmp);
    }

    std::vector<u64> interIndices;
    while (interIndices.size() < interSize) {
        u64 idx = prng.get<u64>() % n;
        if (std::find(interIndices.begin(), interIndices.end(), idx) == interIndices.end()) {
            interIndices.push_back(idx);
        }
    }

    int averageDiff = (lp == 2) ? std::floor(delta * 1.0 / std::sqrt(d)) : std::floor(delta * 1.0 / d);

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (averageDiff + 1));
        }
    }

    std::thread sendLocalMap([&] { LocalMap(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMap(recvSet, recvPid, recvListKey, recvListVal, delta); });

    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(n * d * 3);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey);
    // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    std::vector<block> senderPrfVals(sendListKey.size());
    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(sendListKey, senderPrfVals);
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); i++) {
        sendListVal[i] = sendListVal[i] ^ senderPrfVals[i];
        recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    }

    auto senderOKVS = preOKVS.encode(sendListKey, sendListVal);
    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto s = time.setTimePoint("offline preprocess OKVS done");

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();
    StageProfileSummary stageSummary;

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        StageProfileRun stageRun(stageSummary);
        stageRun.start(totalCommBytes(sock, sock2));

        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);
        std::vector<block> rand_R_j(n);
        std::vector<block> rand_S_j(n);

        AltModPrf RO(prng.get());
        auto key = RO.mExpandedKey;
        AltModPrf::KeyType k1 = prng.get();
        AltModPrf::KeyType k0 = k1 ^ key;

        FuzzyMap(n, d, delta, sendSet, sendPid, senderOKVS, recvSet, recvPid, recverOKVS, ID_R, ID_S, k0, k1, sock, sock2, time);

        // fmap finish
        time.setTimePoint("fmap done");
        stageRun.mark("fmap done", totalCommBytes(sock, sock2));
        // std::cout << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB " <<
        // std::endl;

        std::vector<u8> choiceBit(n, 0);

        std::vector<u64> disR(n, 0);
        std::vector<u64> disS(n, 0);

        std::vector<block> prefixR;
        std::vector<block> prefixS;

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    inputs[i * d + j] = block(high(ID_S[i]) << 8, 0) ^ block(j, sendSet[i][j]); // 8 bits for dimension
                }
            }

            SoOPPRFRecver recv(n * d, n * d * (2 * delta + 1), 1, false, &sock[0]);

            std::vector<block> rand_S(n * d);

            recv.OPPRF(inputs, rand_S);

            std::vector<u64> rand_S_A(n * d);

            oc::Timer localTime;

            auto s = localTime.setTimePoint("b2a start");

            B2aSender b2aSender(n * d, &sock[0]);
            b2aSender.b2a(rand_S, rand_S_A);

            auto e = localTime.setTimePoint("b2a done");

            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000);

            // std::cout << "b2a time: " << dt << " ms" << std::endl;

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disS[i] += rand_S_A[i * d + j];
                }
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getIntervalPrefix(0ULL - disS[i], delta_p - disS[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() < (n * prefixLen)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * prefixLen, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey(n * d * (2 * delta + 1));
            std::vector<block> filterVal(n * d * (2 * delta + 1));
            u64 idx = 0;

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    for (int t = -delta; t <= delta; t++) {
                        block key = block(high(ID_R[i]) << 8, 0) ^ block(j, recvSet[i][j] + t);
                        block val = block(0, std::pow(std::abs(t), lp));
                        filterKey[idx] = key;
                        filterVal[idx] = val;
                        idx++;
                    }
                }
            }

            SoOPPRFSender send(n * d, n * d * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> rand_R(n * d);

            send.OPPRF(filterKey, filterVal, rand_R);

            std::vector<u64> rand_R_A(n * d);

            B2aRecver b2aRecver(n * d, &sock[1]);
            b2aRecver.b2a(rand_R, rand_R_A);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disR[i] += rand_R_A[i * d + j];
                }
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getPrefix(disR[i], prefixLen);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * prefixLen, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLen] = 1;
            }
        });

        sendFilter.join();
        recvFilter.join();

        time.setTimePoint("filter done");
        stageRun.mark("filter done", totalCommBytes(sock, sock2));
        // std::cout << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB " <<
        // std::endl;

        std::thread sendOT([&] {
            SilentOtExtSender send;
            send.configure(n, 128);
            send.mMultType = type;

            coproto::sync_wait(send.genSilentBaseOts(prng, sock[0]));

            std::vector<std::array<block, 2>> messages(n);

            coproto::sync_wait(send.send(messages, prng, sock[0]));

            std::vector<block> correctMessages(n * d / 2 * 2);
            PRNG prng0, prng1;
            for (int i = 0; i < n; i++) {
                prng0.SetSeed(messages[i][0]);
                prng1.SetSeed(messages[i][1]);
                for (int j = 0; j < d / 2; j++) {
                    correctMessages[i * d + j * 2] = prng0.get<block>();
                    correctMessages[i * d + j * 2 + 1] = block(sendSet[i][j * 2], sendSet[i][j * 2 + 1]) ^ prng0.get<block>();
                }
            }
            coproto::sync_wait(sock[0].send(correctMessages));
        });

        std::vector<std::vector<block>> matches;

        std::thread recvOT([&] {
            SilentOtExtReceiver recv;
            recv.configure(n, 128);
            recv.mMultType = type;

            coproto::sync_wait(recv.genSilentBaseOts(prng, sock[1]));

            std::vector<block> messages(n);
            BitVector choices(choiceBit.data(), choiceBit.size());

            coproto::sync_wait(recv.receive(choices, messages, prng, sock[1]));

            std::vector<block> correctMessages(n * d / 2 * 2);
            coproto::sync_wait(sock[1].recv(correctMessages));

            PRNG prng;
            for (int i = 0; i < n; i++) {
                if (choiceBit[i]) {
                    prng.SetSeed(messages[i]);
                    std::vector<block> element;
                    for (int j = 0; j < d / 2; j++) {
                        block val = prng.get<block>() ^ correctMessages[i * d + j * 2 + 1];
                        element.push_back(val);
                    }
                    matches.push_back(element);
                }
            }
        });

        sendOT.join();
        recvOT.join();
        stageRun.mark("OT done", totalCommBytes(sock, sock2));

        if (verbose) {
            for (int i = 0; i < choiceBit.size(); i++) {
                if (choiceBit[i]) {
                    std::cout << "intersection at index " << i << std::endl;
                }
                if (choiceBit[i] && std::find(interIndices.begin(), interIndices.end(), i) == interIndices.end()) {
                    throw runtime_error("false positive in fuzzyPsi");
                }
            }
            std::cout << "All matches found!" << std::endl;

            std::cout << time << std::endl;
            stageSummary.print();
        }
    }

    auto e = time.setTimePoint("OT done");

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;
    const double fmapComm = stageSummary.getAverageCommMB("fmap done");
    const double filterComm = stageSummary.getAverageCommMB("filter done");
    const double otComm = stageSummary.getAverageCommMB("OT done");

    if (lp == 1) {
        printSummaryLine("[ours]", "L1", d, delta, n, comm, comp, fmapComm, filterComm, otComm);
    } else {
        printSummaryLine("[ours]", "L2", d, delta, n, comm, comp, fmapComm, filterComm, otComm);
    }

    // std::cout << "comm: " << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB, "
    //   << " time: " << std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000) << " s" << std::endl;
}
