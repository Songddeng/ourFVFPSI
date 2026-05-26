#include "fpsi_prefix.h"
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <fmt/format.h>
#include <iostream>
#include <macoro/thread_pool.h>
#include <thread>
#include <vector>
#include "OKVS.h"
#include "SiOPRF.h"
#include "SoOPPRF.h"
#include "b2a.h"
#include "eq.h"
#include "mul.h"
#include "mux.h"
#include "param.h"
#include "secure-join/Prf/AltModPrf.h"
#include "utils.h"

using namespace secJoin;

int shift = 1; // modify prefixLen by shift

// to be fixed
void LocalMapPrefix(std::vector<std::vector<u64>> &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta)
{
    PRNG prng(sysRandomSeed());

    u64 m = inputs.size();
    u64 d = inputs[0].size();
    int prefixNum = prefixNumMap.at(2 * delta);
    auto U = prefixLenMap.at(2 * delta);

    pid.resize(m);

    std::vector<std::vector<std::pair<u64, u64>>> intervals(d);

    std::vector<block> randR(m * d);
    prng.get(randR.data(), randR.size());

    u64 maxInter = 0;

    // Merge overlapping intervals
    for (u64 i = 0; i < d; i++) {
        std::vector<std::pair<u64, u64>> interval;
        interval.reserve(m);

        // get interval [a_i - radius, a_i + radius]
        for (auto &elem : inputs) {
            interval.push_back({ elem[i] - delta, elem[i] + delta });
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

    for (u64 j = 0; j < m; j++) {
        auto &elem = inputs[j];
        for (u64 i = 0; i < d; i++) {
            auto it = std::lower_bound(intervals[i].begin(), intervals[i].end(), elem[i], compare_lambda);

            if (it != intervals[i].end() && it->first <= elem[i]) {
                auto interval_index = distance(intervals[i].begin(), it);
                pid[j] ^= randR[i * m + interval_index];
            } else {
                std::cout << i << " " << elem[i] << std::endl;
                throw runtime_error("recv getID random error");
            }
        }
    }

    // build listKey and listVal
    for (u64 i = 0; i < d; i++) {
        for (u64 j = 0; j < intervals[i].size(); j++) {
            auto [start, end] = intervals[i][j];
            auto randR_i_j = randR[i * m + j];
            u32 segNum = static_cast<u32>(std::ceil((end - start + 1) / double(2 * delta + 1))); // every sub interval at most length of (2*delta+1)
            for (u64 k = 0; k < segNum; k++) {
                u64 segStart = start + k * (2 * delta + 1);
                u64 segEnd = std::min(end, segStart + (2 * delta));
                auto prefixes = getIntervalPrefixSet(segStart, segEnd, U);
                for (auto &p : prefixes) {
                    block key = block(i << 32, 0) ^ p;
                    block val = ZeroBlock;
                    listKey.push_back(key);
                    listVal.push_back(val);
                    key = block((1 << 16) | (i << 32), 0) ^ p;
                    val = randR_i_j;
                    listKey.push_back(key);
                    listVal.push_back(val);
                }
            }
        }
    }

    if (listKey.size() > prefixNum * d * m * 2) {
        throw runtime_error("something wrong in LocalMapPrefix");
    }

    while (listKey.size() < prefixNum * d * m * 2) {
        listKey.push_back(prng.get<block>());
        listVal.push_back(prng.get<block>());
    }
    Hash(listKey);
}

void FuzzyMapPrefix(
    u64 n,
    size_t d,
    int delta,
    int prefixLen,
    int prefixNum,
    std::vector<u64> &U,
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
        SoOPPRFRecver recv(2 * n * d * prefixLen, 2 * n * d * prefixNum, 1, false, &sock[0]);

        std::vector<block> inputs(2 * n * d * prefixLen);
        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                auto prefixes = getPrefixSet(sendSet[i][j], U);
                for (int k = 0; k < prefixLen; k++) {
                    inputs[i * d * prefixLen + j * prefixLen + k] = block(j << 32, 0) ^ prefixes[k];
                    inputs[(n + i) * d * prefixLen + j * prefixLen + k] = block((1 << 16) | (j << 32), 0) ^ prefixes[k];
                }
            }
        }

        std::vector<block> rand_S(2 * n * d * prefixLen);

        Hash(inputs);
        recv.OPPRF(inputs, rand_S);

        std::vector<block> u(n * d * prefixLen);
        std::vector<block> v(n * d * prefixLen);

        for (u64 i = 0; i < n * d * prefixLen; i++) {
            u[i] = rand_S[i];
            v[i] = rand_S[i + n * d * prefixLen];
        }

        MuxSender mux(n * d * prefixLen, &sock[0]);

        std::vector<block> t(n * d);

        mux.mux(u, v, t, prefixLen);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_S_j[i] ^= t[i * d + j];
            }
            rand_S_j[i] = rand_S_j[i] ^ sendPid[i];
        }
    });

    std::thread recvSoOPPRFReverse([&] {
        SoOPPRFSender send(2 * n * d * prefixLen, 2 * n * d * prefixNum, 1, false, &sock[1]);

        std::vector<block> rand_R(2 * n * d * prefixLen);

        // send.OPPRF(recvListKey, recvListVal, rand_R);
        send.OPPRF(recverOKVS, rand_R);

        std::vector<block> u(n * d * prefixLen);
        std::vector<block> v(n * d * prefixLen);

        for (u64 i = 0; i < n * d * prefixLen; i++) {
            u[i] = rand_R[i];
            v[i] = rand_R[i + n * d * prefixLen];
        }

        MuxRecver mux(n * d * prefixLen, &sock[1]);

        std::vector<block> t(n * d);

        mux.mux(u, v, t, prefixLen);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_R_j[i] ^= t[i * d + j];
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
        SoOPPRFSender send(2 * n * d * prefixLen, 2 * n * d * prefixNum, 1, false, &sock[0]);

        std::vector<block> rand_S(2 * n * d * prefixLen);

        // send.OPPRF(sendListKey, sendListVal, rand_S);
        send.OPPRF(senderOKVS, rand_S);

        std::vector<block> u(n * d * prefixLen);
        std::vector<block> v(n * d * prefixLen);

        for (u64 i = 0; i < n * d * prefixLen; i++) {
            u[i] = rand_S[i];
            v[i] = rand_S[i + n * d * prefixLen];
        }

        MuxSender mux(n * d * prefixLen, &sock[0]);

        std::vector<block> t(n * d);

        mux.mux(u, v, t, prefixLen);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_S_j[i] ^= t[i * d + j];
            }
        }
    });

    std::thread recvSoOPPRF([&] {
        SoOPPRFRecver recv(2 * n * d * prefixLen, 2 * n * d * prefixNum, 1, false, &sock[1]);

        std::vector<block> inputs(2 * n * d * prefixLen);
        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                auto prefixes = getPrefixSet(recvSet[i][j], U);
                for (int k = 0; k < prefixLen; k++) {
                    inputs[i * d * prefixLen + j * prefixLen + k] = block(j << 32, 0) ^ prefixes[k];
                    inputs[(n + i) * d * prefixLen + j * prefixLen + k] = block((1 << 16) | (j << 32), 0) ^ prefixes[k];
                }
            }
        }
        std::vector<block> rand_R(2 * n * d * prefixLen);

        Hash(inputs);
        recv.OPPRF(inputs, rand_R);

        std::vector<block> u(n * d * prefixLen);
        std::vector<block> v(n * d * prefixLen);

        for (u64 i = 0; i < n * d * prefixLen; i++) {
            u[i] = rand_R[i];
            v[i] = rand_R[i + n * d * prefixLen];
        }

        MuxRecver mux(n * d * prefixLen, &sock[1]);

        std::vector<block> t(n * d);

        mux.mux(u, v, t, prefixLen);

        for (u64 i = 0; i < n; i++) {
            for (u64 j = 0; j < d; j++) {
                rand_R_j[i] ^= t[i * d + j];
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

void fuzzyPsiPrefix(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    shift = cmd.getOr("s", 0);

    // int prefixNum = static_cast<int>(std::ceil(std::log2(delta * 2 + 1))) + (1 << shift);
    // int prefixLen = static_cast<int>(std::floor(std::log2(delta * 2 + 1))) - shift + 1;
    auto U = prefixLenMap.at(2 * delta);
    int prefixLen = U.size();
    int prefixNum = prefixNumMap.at(2 * delta);

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

    std::thread sendLocalMap([&] { LocalMapPrefix(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMapPrefix(recvSet, recvPid, recvListKey, recvListVal, delta); });

    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(2 * n * d * prefixNum);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey); // local encoding from set, totally offline

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

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        std::vector<block> rand_R_j(n);
        std::vector<block> rand_S_j(n);
        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);

        AltModPrf RO(prng.get());
        auto key = RO.mExpandedKey;
        AltModPrf::KeyType k1 = prng.get();
        AltModPrf::KeyType k0 = k1 ^ key;

        FuzzyMapPrefix(n, d, delta, prefixLen, prefixNum, U, sendSet, sendPid, senderOKVS, recvSet, recvPid, recverOKVS, ID_R, ID_S, k0, k1, sock, sock2, time);

        // for (u64 i = 0; i < n; i++) {
        //     std::cout << "Sender ID: " << ID_S[i] << " Receiver ID: " << ID_R[i] << " ";
        //     if (ID_S[i] == ID_R[i]) {
        //         std::cout << "<-- in intersection"
        //                   << " " << i << std::endl;
        //     } else {
        //         std::cout << std::endl;
        //     }
        // }

        rand_R_j = std::vector<block>(n);
        rand_S_j = std::vector<block>(n);

        // fmap finish
        time.setTimePoint("fmap-prefix done");
        // std::cout << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB " <<
        // std::endl;

        std::vector<u8> choiceBit(n, 0);

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d * prefixLen);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], U);
                    for (int k = 0; k < prefixLen; k++) {
                        inputs[i * d * prefixLen + j * prefixLen + k] = block(high(ID_S[i]) << 8, 0) ^ block(j << 4, 0) ^ prefixes[k];
                    }
                }
            }

            SoOPPRFRecver recv(n * d * prefixLen, n * d * prefixNum, 1, false, &sock[0]);

            std::vector<block> rand_S(n * d * prefixLen);

            recv.OPPRF(inputs, rand_S);

            std::vector<block> u(n * d * prefixLen);
            std::vector<block> v(n * d * prefixLen);

            for (u64 i = 0; i < n * d * prefixLen; i++) {
                u[i] = block(0, high(rand_S[i]));
                v[i] = block(0, low(rand_S[i]));
            }

            MuxSender mux(n * d * prefixLen, &sock[0]);
            std::vector<block> t(n * d);

            mux.mux(u, v, t, prefixLen);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_S_j[i] ^= t[i * d + j];
                }
            }

            PEqTSender eqSend(n, 1, false, &sock[0]);

            eqSend.eq(rand_S_j);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey;
            std::vector<block> filterVal;

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] + delta, U);
                    for (auto &p : prefixes) {
                        block key = block(high(ID_R[i]) << 8, 0) ^ block(j << 4, 0) ^ p;
                        block val = ZeroBlock;
                        filterKey.push_back(key);
                        filterVal.push_back(val);
                    }
                }
            }

            while (filterKey.size() < n * d * prefixNum) {
                filterKey.push_back(prng.get<block>());
                filterVal.push_back(prng.get<block>());
            }

            SoOPPRFSender send(n * d * prefixLen, n * d * prefixNum, 1, false, &sock[1]);

            std::vector<block> rand_R(n * d * prefixLen);

            send.OPPRF(filterKey, filterVal, rand_R);

            std::vector<block> u(n * d * prefixLen);
            std::vector<block> v(n * d * prefixLen);

            for (u64 i = 0; i < n * d * prefixLen; i++) {
                u[i] = block(0, high(rand_R[i]));
                v[i] = block(0, low(rand_R[i]));
            }

            MuxRecver mux(n * d * prefixLen, &sock[1]);
            std::vector<block> t(n * d);

            mux.mux(u, v, t, prefixLen);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_R_j[i] ^= t[i * d + j];
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
        }
    }

    auto e = time.setTimePoint("OT done");

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << fmt::format(
                     "[ours-prefix]    L0    {:^5}  {:^5}  {:^5}  {:^10.3f} "
                     "{:^10.3f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;

    // std::cout << "comm: " << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB, "
    //   << " time: " << std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000) << " s" << std::endl;
}

void fuzzyPsiLpPrefix(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int lp = cmd.getOr("p", 2);
    int verbose = cmd.getOr("v", 0);

    u64 delta_p = std::pow(delta, lp);

    int numTry = cmd.getOr("try", 1);

    shift = cmd.getOr("s", 0);

    // int prefixNum = static_cast<int>(std::ceil(std::log2(delta * 2 + 1))) + (1 << shift);
    // int prefixLen = static_cast<int>(std::floor(std::log2(delta * 2 + 1))) - shift + 1;
    auto U = prefixLenMap.at(2 * delta);
    int prefixLen = U.size();
    int prefixNum = prefixNumMap.at(2 * delta);

    int prefixLenIfmat = static_cast<int>(std::ceil(std::log2(delta_p * 2 + 1)));

    // int prefixNumUpDown = 2 * (static_cast<int>(std::ceil(std::log2(delta + 1))) + (1 << shift));
    // int prefixLenUpDown = 2 * (static_cast<int>(std::floor(std::log2(delta + 1))) - shift + 1);
    auto U_prime = prefixLenMap.at(delta);
    int prefixLenUpDown = 2 * U_prime.size();
    int prefixNumUpDown = 2 * prefixNumMap.at(delta);

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

    int averageDiff = (lp == 2) ? std::floor(delta * 1.0 / std::sqrt(d)) : std::floor(delta * 1.0 / d);

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (averageDiff + 1));
        }
    }

    std::thread sendLocalMap([&] { LocalMapPrefix(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMapPrefix(recvSet, recvPid, recvListKey, recvListVal, delta); });

    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(2 * n * d * prefixNum);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey); // local encoding from set, totally offline

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

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        std::vector<block> rand_R_j(n);
        std::vector<block> rand_S_j(n);
        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);

        AltModPrf RO(prng.get());
        auto key = RO.mExpandedKey;
        AltModPrf::KeyType k1 = prng.get();
        AltModPrf::KeyType k0 = k1 ^ key;

        FuzzyMapPrefix(n, d, delta, prefixLen, prefixNum, U, sendSet, sendPid, senderOKVS, recvSet, recvPid, recverOKVS, ID_R, ID_S, k0, k1, sock, sock2, time);

        // for (u64 i = 0; i < n; i++) {
        //     std::cout << "Sender ID: " << ID_S[i] << " Receiver ID: " << ID_R[i] << " ";
        //     if (ID_S[i] == ID_R[i]) {
        //         std::cout << "<-- in intersection"
        //                   << " " << i << std::endl;
        //     } else {
        //         std::cout << std::endl;
        //     }
        // }

        rand_R_j = std::vector<block>(n);
        rand_S_j = std::vector<block>(n);

        // fmap finish

        time.setTimePoint("fmap-prefix done");
        // std::cout << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB " <<
        // std::endl;

        std::vector<u8> choiceBit(n, 0);

        std::vector<u64> disR(n, 0);
        std::vector<u64> disS(n, 0);

        std::vector<block> prefixR;
        std::vector<block> prefixS;

        int OkvsBatch = lp / 2 + 1;
        int halfprefixLen = prefixLenUpDown / 2;
        int halfprefixNum = prefixNumUpDown / 2;

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d * halfprefixLen * 2 * OkvsBatch);

            for (int batch = 0; batch < OkvsBatch; batch++) {
                for (int i = 0; i < n; i++) {
                    for (int j = 0; j < d; j++) {
                        auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                        for (int s = 0; s < 2; s++) {
                            for (int k = 0; k < halfprefixLen; k++) {
                                auto idx = batch * n * d * halfprefixLen * 2 + i * d * halfprefixLen * 2 + j * halfprefixLen * 2 + s * halfprefixLen + k;
                                inputs[idx] = block(high(ID_S[i]) << 12, 0) ^ block((j << 8) | (batch << 6) | (s << 4), 0) ^ prefixes[k]; //  batch, i, j, s, k
                            }
                        }
                    }
                }
            }

            SoOPPRFRecver recv(OkvsBatch * n * d * 2 * halfprefixLen, OkvsBatch * n * d * 2 * halfprefixNum, 1, false, &sock[0]);

            std::vector<block> rand_S(OkvsBatch * n * d * 2 * halfprefixLen);

            recv.OPPRF(inputs, rand_S);

            std::vector<block> u(n * d * prefixLenUpDown);
            std::vector<block> v(n * d * prefixLenUpDown * lp);

            for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_S[i]));
            }
            if (lp == 1) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_S[i]));
                }
            } else if (lp == 2) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_S[i]));
                }
                for (u64 i = 1 * n * d * 2 * halfprefixLen; i < 2 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, high(rand_S[i]));
                }
            } else {
                throw std::runtime_error("lp not supported");
            }

            // std::vector<block> v_selected(n * d * lp);

            // MuxSender mux(n * d * prefixLenUpDown, &sock[0]);
            // if (lp == 1) {
            //     mux.mux(u, v, v_selected, prefixLenUpDown);
            // } else if (lp == 2) {
            //     std::vector<block> res0(n * d);
            //     std::vector<block> res1(n * d);
            //     std::vector<block> v1(v.begin(), v.begin() + n * d * prefixLenUpDown);
            //     std::vector<block> v2(v.begin() + n * d * prefixLenUpDown, v.end());
            //     mux.mux(u, v1, res0, prefixLen);
            //     mux.mux(u, v2, res1, prefixLen);
            //     for (u64 i = 0; i < n * d; i++) {
            //         v_selected[i] = res0[i];
            //         v_selected[i + n * d] = res1[i];
            //     }
            // }

            std::vector<u64> v_A(n * d * prefixLenUpDown * lp);

            oc::Timer localTime;

            auto start = localTime.setTimePoint("b2a start");

            B2aSender b2aSender(n * d * prefixLenUpDown * lp, &sock[0]);
            b2aSender.b2a(v, v_A);

            auto end = localTime.setTimePoint("b2a done");

            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);

            // std::cout << "b2a time: " << dt << " ms" << std::endl;

            std::vector<u64> sumDis(n * d * 2 * halfprefixLen, 0);
            std::vector<u64> e(n * d * 2 * halfprefixLen, 0);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                    for (int s = 0; s < 2; s++) {
                        for (int k = 0; k < halfprefixLen; k++) {
                            e[i * d * prefixLenUpDown + j * prefixLenUpDown + s * halfprefixLen + k] =
                                (s == 0) ? upBound(prefixes[k]) - sendSet[i][j] : sendSet[i][j] - upBound(prefixes[k]);
                        }
                    }
                }
            }

            if (lp == 1) {
                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i] + e[i];
                }
            }
            if (lp == 2) {
                MulSender mulSender(n * d * prefixLenUpDown, &sock[0]);
                std::vector<u64> product(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_1(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_2(n * d * prefixLenUpDown, 0);

                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v_A_1[i] = v_A[i];
                    v_A_2[i] = v_A[i + 1 * n * d * 2 * halfprefixLen];
                }

                mulSender.mul(e, product);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = e[i] * e[i] + 2 * e[i] * v_A_1[i] + 2 * product[i] + v_A_2[i];
                }
            }

            std::vector<u64> rand_i_j(n * d, 0);

            MuxSender mux(n * d * prefixLenUpDown, &sock[0]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disS[i] += rand_i_j[i * d + j];
                }
                // disS[i] = v_A[i];
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getIntervalPrefix(0ULL - disS[i], delta_p - disS[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() != (n * prefixLenIfmat)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * prefixLenIfmat, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey;
            std::vector<block> filterVal;

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes0 = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] - 1, U_prime);
                    auto prefixes1 = getIntervalPrefixSet(recvSet[i][j], recvSet[i][j] + delta, U_prime);
                    for (auto &p : prefixes0) {
                        auto upbound = upBound(p);
                        for (int batch = 0; batch < OkvsBatch; batch++) {
                            block key = block(high(ID_R[i]) << 12, 0) ^ block((j << 8) | (batch << 6) | (0 << 4), 0) ^ p;
                            block val = ZeroBlock;
                            if (batch == 0) {
                                val = block(0, std::pow(recvSet[i][j] - upbound, batch + 1));
                            } else {
                                val = block(std::pow(recvSet[i][j] - upbound, batch + 1), 0);
                            }
                            filterKey.push_back(key);
                            filterVal.push_back(val);
                        }
                    }
                    for (auto &p : prefixes1) {
                        auto upbound = upBound(p);
                        for (int batch = 0; batch < OkvsBatch; batch++) {
                            block key = block(high(ID_R[i]) << 12, 0) ^ block((j << 8) | (batch << 6) | (1 << 4), 0) ^ p;
                            block val = ZeroBlock;
                            if (batch == 0) {
                                val = block(0, std::pow(upbound - recvSet[i][j], batch + 1));
                            } else {
                                val = block(std::pow(upbound - recvSet[i][j], batch + 1), 0);
                            }
                            filterKey.push_back(key);
                            filterVal.push_back(val);
                        }
                    }
                }
            }

            if (filterKey.size() > n * d * prefixNumUpDown * OkvsBatch) {
                throw std::runtime_error("filterKey size wrong");
            }

            while (filterKey.size() < n * d * prefixNumUpDown * OkvsBatch) {
                filterKey.push_back(prng.get<block>());
                filterVal.push_back(prng.get<block>());
            }

            if (filterVal.size() != n * d * prefixNumUpDown * OkvsBatch) {
                throw std::runtime_error("filterVal size wrong");
            }

            SoOPPRFSender send(n * d * prefixLenUpDown * OkvsBatch, n * d * prefixNumUpDown * OkvsBatch, 1, false, &sock[1]);

            std::vector<block> rand_R(n * d * prefixLenUpDown * OkvsBatch);

            send.OPPRF(filterKey, filterVal, rand_R);

            std::vector<block> u(n * d * prefixLenUpDown);
            std::vector<block> v(n * d * prefixLenUpDown * lp);

            for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_R[i]));
            }
            if (lp == 1) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_R[i]));
                }
            } else if (lp == 2) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_R[i]));
                }
                for (u64 i = 1 * n * d * 2 * halfprefixLen; i < 2 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, high(rand_R[i]));
                }
            } else {
                throw std::runtime_error("lp not supported");
            }

            std::vector<u64> v_A(n * d * prefixLenUpDown * lp);

            B2aRecver b2aRecver(n * d * prefixLenUpDown * lp, &sock[1]);
            b2aRecver.b2a(v, v_A);

            std::vector<u64> sumDis(n * d * prefixLenUpDown, 0);

            if (lp == 1) {
                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i];
                }
            }
            if (lp == 2) {
                MulRecver mulRecver(n * d * prefixLenUpDown, &sock[1]);
                std::vector<u64> product(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_1(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_2(n * d * prefixLenUpDown, 0);

                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v_A_1[i] = v_A[i];
                    v_A_2[i] = v_A[i + 1 * n * d * 2 * halfprefixLen];
                }

                mulRecver.mul(v_A_1, product);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = 2 * product[i] + v_A_2[i];
                }
            }

            std::vector<u64> rand_i_j(n * d, 0);

            MuxRecver mux(n * d * prefixLenUpDown, &sock[1]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disR[i] += rand_i_j[i * d + j];
                }
                // disR[i] = v_A[i];
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getPrefix(disR[i], prefixLenIfmat);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * prefixLenIfmat, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLenIfmat] = 1;
            }
        });

        sendFilter.join();
        recvFilter.join();

        time.setTimePoint("filter done");
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
        }
    }

    auto e = time.setTimePoint("OT done");

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    if (lp == 1) {
        std::cout << fmt::format(
                         "[ours-prefix]    L1    {:^5}  {:^5}  {:^5}  {:^10.3f} "
                         "{:^10.3f}",
                         d,
                         delta,
                         n,
                         comm,
                         comp)
                  << std::endl;
    } else {
        std::cout << fmt::format(
                         "[ours-prefix]    L2    {:^5}  {:^5}  {:^5}  {:^10.3f} "
                         "{:^10.3f}",
                         d,
                         delta,
                         n,
                         comm,
                         comp)
                  << std::endl;
    }
    // std::cout << "comm: " << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB, "
    //           << " time: " << std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000) << " s" << std::endl;
}
