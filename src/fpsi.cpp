#include "fpsi.h"
#include <algorithm>
#include <cmath>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <numeric>
#include <unordered_map>
#include <unordered_set>
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
#include "id_stats.h"
#include "prefilter_bench.h"
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

uint64_t countSelections(const std::vector<u8> &selectionBits)
{
    return static_cast<uint64_t>(std::count(selectionBits.begin(), selectionBits.end(), static_cast<u8>(1)));
}

void printStageDiagnostics(int verbose, const oc::Timer &time, const StageProfileSummary &stageSummary)
{
    if (verbose >= 1) {
        printTimerProfile(time);
        std::cout << std::endl;
        stageSummary.print();
    }

    if (verbose >= 2) {
        std::cout << std::endl << time << std::endl;
    }
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
    printProtocolSummaryLine(std::cout, proto, metric, d, delta, n, comm, comp, fmapComm, filterComm, otComm);
}

std::string toLowerCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

enum class IntersectionRevealMode {
    Mutual,
    ReceiverOnly,
};

enum class ExecutionPath {
    Legacy,
    ReceiverFuseHandoff,
};

const char *intersectionRevealModeName(IntersectionRevealMode mode)
{
    switch (mode) {
    case IntersectionRevealMode::Mutual:
        return "mutual";
    case IntersectionRevealMode::ReceiverOnly:
        return "receiver_only";
    }
    throw std::runtime_error("unknown intersection reveal mode");
}

IntersectionRevealMode parseIntersectionRevealMode(const oc::CLP &cmd)
{
    if (cmd.isSet("reveal_mode")) {
        const std::string revealMode = toLowerCopy(cmd.get<std::string>("reveal_mode"));
        if (revealMode == "0" || revealMode == "mutual" || revealMode == "symmetric" || revealMode == "mutual_psi") {
            return IntersectionRevealMode::Mutual;
        }
        if (revealMode == "1" || revealMode == "receiver_only" || revealMode == "traditional" || revealMode == "traditional_psi") {
            return IntersectionRevealMode::ReceiverOnly;
        }

        throw std::runtime_error("unsupported -reveal_mode; use mutual|receiver_only (or 0|1)");
    }

    if (!cmd.isSet("safe_filter") && !cmd.isSet("sf")) {
        return IntersectionRevealMode::ReceiverOnly;
    }

    const int legacySf = cmd.getOr<int>("safe_filter", cmd.getOr<int>("sf", 1));
    if (legacySf == 0) {
        return IntersectionRevealMode::Mutual;
    }
    if (legacySf == 1) {
        return IntersectionRevealMode::ReceiverOnly;
    }

    throw std::runtime_error("legacy -sf must be 0 or 1");
}

ExecutionPath parseExecutionPath(const oc::CLP &cmd)
{
    const std::string execPath = toLowerCopy(cmd.getOr<std::string>("exec_path", "legacy"));
    if (
        execPath == "legacy" ||
        execPath == "default") {
        return ExecutionPath::Legacy;
    }

    if (
        execPath == "receiver_fuse_handoff" ||
        execPath == "receiver-fuse-handoff" ||
        execPath == "fuse_handoff" ||
        execPath == "fuse-handoff" ||
        execPath == "bfuse_handoff" ||
        execPath == "bfuse-handoff") {
        return ExecutionPath::ReceiverFuseHandoff;
    }

    throw std::runtime_error("unsupported -exec_path; use legacy|receiver_fuse_handoff");
}

template <typename T>
std::vector<T> selectByIndex(const std::vector<T> &input, const std::vector<uint32_t> &indices)
{
    std::vector<T> output;
    output.reserve(indices.size());
    for (uint32_t index : indices) {
        output.push_back(input[index]);
    }
    return output;
}

std::vector<std::vector<u64>> selectRowsByIndex(const std::vector<std::vector<u64>> &input, const std::vector<uint32_t> &indices)
{
    std::vector<std::vector<u64>> output;
    output.reserve(indices.size());
    for (uint32_t index : indices) {
        output.push_back(input[index]);
    }
    return output;
}

struct BlockKey {
    uint64_t lo = 0;
    uint64_t hi = 0;

    bool operator==(const BlockKey &other) const = default;
};

struct BlockKeyHash {
    size_t operator()(const BlockKey &value) const noexcept
    {
        const size_t loHash = std::hash<uint64_t> {}(value.lo);
        const size_t hiHash = std::hash<uint64_t> {}(value.hi);
        return loHash ^ (hiHash + 0x9e3779b97f4a7c15ULL + (loHash << 6) + (loHash >> 2));
    }
};

BlockKey toBlockKey(const block &value)
{
    return { low(value), high(value) };
}

std::vector<block> collectDistinctBlocks(const std::vector<block> &values)
{
    std::vector<block> distinct;
    distinct.reserve(values.size());

    std::unordered_set<BlockKey, BlockKeyHash> seen;
    seen.reserve(values.size());

    for (const block &value : values) {
        const BlockKey key = toBlockKey(value);
        if (seen.insert(key).second) {
            distinct.push_back(value);
        }
    }

    return distinct;
}

std::vector<uint32_t> selectIndicesForOrderedIdsWithRandomFallback(
    const std::vector<block> &orderedCandidateIds,
    const std::vector<block> &localIds,
    PRNG &prng)
{
    if (localIds.empty()) {
        throw std::runtime_error("cannot materialize sender candidate stream from empty local IDs");
    }

    std::unordered_map<BlockKey, std::vector<uint32_t>, BlockKeyHash> localBuckets;
    localBuckets.reserve(localIds.size());
    for (uint32_t i = 0; i < localIds.size(); ++i) {
        localBuckets[toBlockKey(localIds[i])].push_back(i);
    }

    std::unordered_map<BlockKey, size_t, BlockKeyHash> bucketOffsets;
    bucketOffsets.reserve(localBuckets.size());

    std::vector<uint32_t> selectedIndices;
    selectedIndices.reserve(orderedCandidateIds.size());

    for (const block &id : orderedCandidateIds) {
        const BlockKey key = toBlockKey(id);
        auto bucketIt = localBuckets.find(key);
        if (bucketIt == localBuckets.end()) {
            selectedIndices.push_back(static_cast<uint32_t>(prng.get<u64>() % localIds.size()));
            continue;
        }

        size_t &offset = bucketOffsets[key];
        if (offset < bucketIt->second.size()) {
            selectedIndices.push_back(bucketIt->second[offset]);
            ++offset;
            continue;
        }

        selectedIndices.push_back(static_cast<uint32_t>(prng.get<u64>() % localIds.size()));
    }

    return selectedIndices;
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
        fpsi::stats::id_generated_total.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);
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
        fpsi::stats::id_generated_total.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);
    });

    sendSiOPRF.join();
    recvSiOPRF.join();

    time.setTimePoint("siOPRF done");
}

void fuzzyPsi(const oc::CLP &cmd)
{
    fpsi::stats::reset_id_stats();

    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);
    const IntersectionRevealMode revealMode = parseIntersectionRevealMode(cmd);
    const bool mutualReveal = revealMode == IntersectionRevealMode::Mutual;
    const bool receiverOnlyReveal = revealMode == IntersectionRevealMode::ReceiverOnly;
    const std::string prefilterMode = toLowerCopy(cmd.getOr<std::string>("prefilter", ""));
    const bool enablePrefilter = !prefilterMode.empty();
    fpsi::prefilter::PrefilterKind prefilterKind = fpsi::prefilter::PrefilterKind::BinaryFuse;
    constexpr double kBinaryFuseHelperFpr = 1e-3;

    if (cmd.isSet("fpr")) {
        throw std::runtime_error("fuzzyPsi does not support -fpr; the Binary Fuse prefilter uses a fixed configuration");
    }

    if (prefilterMode.empty()) {
        if (mutualReveal) {
            throw std::runtime_error("mutual reveal mode requires -prefilter bfuse");
        }
    } else if (
        prefilterMode == "bfuse" ||
        prefilterMode == "binaryfuse" ||
        prefilterMode == "binary_fuse" ||
        prefilterMode == "binary-fuse" ||
        prefilterMode == "fuse") {
        prefilterKind = fpsi::prefilter::PrefilterKind::BinaryFuse;
    } else {
        throw std::runtime_error("fuzzyPsi currently supports only -prefilter bfuse");
    }

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

    std::unordered_set<uint64_t> trueIntersectionIndexSet;
    trueIntersectionIndexSet.reserve(interIndices.size());
    for (u64 idx : interIndices) {
        trueIntersectionIndexSet.insert(static_cast<uint64_t>(idx));
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
    uint64_t prefilterGeneratedAcc = 0;
    uint64_t prefilterFilteredAcc = 0;
    fpsi::stats::FilterAuditStats filterAuditTotals;
    uint64_t mutualIntersectionHitsTotal = 0;

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        StageProfileRun stageRun(stageSummary);
        stageRun.start(totalCommBytes(sock, sock2));
        fpsi::stats::id_used_total.fetch_add(static_cast<uint64_t>(interIndices.size()) * 2, std::memory_order_relaxed);

        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);

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

        u64 workN = n;
        std::vector<uint32_t> activeIndices(n);
        std::iota(activeIndices.begin(), activeIndices.end(), 0);
        std::vector<std::vector<u64>> filteredSendSet;
        std::vector<std::vector<u64>> filteredRecvSet;
        std::vector<block> filteredIdS;
        std::vector<block> filteredIdR;
        std::vector<uint8_t> receiverPrefilterHitMask(n, 1);
        bool skipReceiverOnlyFilterStage = false;

        const std::vector<std::vector<u64>> *workSendSet = &sendSet;
        const std::vector<std::vector<u64>> *workRecvSet = &recvSet;
        const std::vector<block> *workIdS = &ID_S;
        const std::vector<block> *workIdR = &ID_R;

        if (enablePrefilter) {
            const std::vector<block> distinctSenderIds = collectDistinctBlocks(ID_S);
            const std::vector<block> distinctReceiverIds = collectDistinctBlocks(ID_R);
            uint64_t receiverDistinctHits = 0;
            std::vector<uint32_t> receiverKeptIndices;
            std::vector<uint32_t> senderKeptIndices;

            if (receiverOnlyReveal) {
                receiverPrefilterHitMask.assign(n, 0);

                std::thread sendPrefilter([&] {
                    const auto serializedFilter = fpsi::prefilter::buildSerializedPrefilter(
                        prefilterKind,
                        ID_S,
                        kBinaryFuseHelperFpr);
                    const uint64_t filterBytes = serializedFilter.size();
                    coproto::sync_wait(sock[0].send(filterBytes));
                    coproto::sync_wait(sock[0].send(serializedFilter));
                });

                std::thread recvPrefilter([&] {
                    uint64_t filterBytes = 0;
                    coproto::sync_wait(sock[1].recv(filterBytes));
                    std::vector<uint8_t> serializedFilter(filterBytes);
                    coproto::sync_wait(sock[1].recv(serializedFilter));

                    const auto distinctHitIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        distinctReceiverIds);
                    receiverDistinctHits = distinctHitIndices.size();

                    receiverKeptIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        ID_R);
                    for (uint32_t index : receiverKeptIndices) {
                        receiverPrefilterHitMask[index] = 1;
                    }
                });

                sendPrefilter.join();
                recvPrefilter.join();
                skipReceiverOnlyFilterStage = receiverKeptIndices.empty();
            } else {
                const block senderPrefilterDummySeed = prng.get<block>();
                std::thread sendPrefilter([&] {
                    PRNG localDummyPrng(senderPrefilterDummySeed);
                    const auto serializedFilter = fpsi::prefilter::buildSerializedPrefilter(
                        prefilterKind,
                        ID_S,
                        kBinaryFuseHelperFpr);
                    const uint64_t filterBytes = serializedFilter.size();
                    coproto::sync_wait(sock[0].send(filterBytes));
                    coproto::sync_wait(sock[0].send(serializedFilter));

                    uint64_t candidateIdCount = 0;
                    coproto::sync_wait(sock[0].recv(candidateIdCount));
                    std::vector<block> receiverCandidateIds(candidateIdCount);
                    if (candidateIdCount != 0) {
                        coproto::sync_wait(sock[0].recv(receiverCandidateIds));
                    }

                    senderKeptIndices = selectIndicesForOrderedIdsWithRandomFallback(
                        receiverCandidateIds,
                        ID_S,
                        localDummyPrng);
                });

                std::thread recvPrefilter([&] {
                    uint64_t filterBytes = 0;
                    coproto::sync_wait(sock[1].recv(filterBytes));
                    std::vector<uint8_t> serializedFilter(filterBytes);
                    coproto::sync_wait(sock[1].recv(serializedFilter));

                    const auto distinctHitIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        distinctReceiverIds);
                    receiverDistinctHits = distinctHitIndices.size();

                    receiverKeptIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        ID_R);

                    const std::vector<block> receiverCandidateIds = selectByIndex(ID_R, receiverKeptIndices);
                    const uint64_t candidateIdCount = receiverCandidateIds.size();
                    coproto::sync_wait(sock[1].send(candidateIdCount));
                    if (candidateIdCount != 0) {
                        coproto::sync_wait(sock[1].send(receiverCandidateIds));
                    }
                });

                sendPrefilter.join();
                recvPrefilter.join();
                filteredSendSet = selectRowsByIndex(sendSet, senderKeptIndices);
                filteredRecvSet = selectRowsByIndex(recvSet, receiverKeptIndices);
                filteredIdS = selectByIndex(ID_S, senderKeptIndices);
                filteredIdR = selectByIndex(ID_R, receiverKeptIndices);
                activeIndices = selectByIndex(activeIndices, receiverKeptIndices);

                workN = filteredIdR.size();
                workSendSet = &filteredSendSet;
                workRecvSet = &filteredRecvSet;
                workIdS = &filteredIdS;
                workIdR = &filteredIdR;
            }

            prefilterGeneratedAcc += static_cast<uint64_t>(n) * 2;
            prefilterFilteredAcc += (receiverOnlyReveal ? static_cast<uint64_t>(n) * 2 : workN * 2);
            fpsi::stats::id_generated_total.store(prefilterGeneratedAcc, std::memory_order_relaxed);
            fpsi::stats::id_filtered_total.store(prefilterFilteredAcc, std::memory_order_relaxed);

            filterAuditTotals.s_id_generated_distinct += distinctSenderIds.size();
            filterAuditTotals.r_id_generated_distinct += distinctReceiverIds.size();
            filterAuditTotals.true_intersection_estimate += static_cast<uint64_t>(interIndices.size());
            filterAuditTotals.r_total_hits += receiverDistinctHits;
            filterAuditTotals.r_filtered_useless_ids += static_cast<uint64_t>(distinctReceiverIds.size()) - receiverDistinctHits;
            stageRun.mark("prefilter done", totalCommBytes(sock, sock2));
        }

        if (workN == 0) {
            time.setTimePoint("filter done");
            stageRun.mark("filter done", totalCommBytes(sock, sock2));
            time.setTimePoint("OT done");
            stageRun.mark("OT done", totalCommBytes(sock, sock2));
            continue;
        }

        std::vector<u8> choiceBit(workN, 0);
        std::vector<block> rand_R_j(workN);
        std::vector<block> rand_S_j(workN);

        std::thread sendFilter([&] {
            if (skipReceiverOnlyFilterStage) {
                return;
            }

            std::vector<block> inputs(workN * d);

            for (u64 i = 0; i < workN; i++) {
                for (int j = 0; j < d; j++) {
                    inputs[i * d + j] = block(high((*workIdS)[i]) << 8, 0) ^ block(j, (*workSendSet)[i][j]); // 8 bits for dimension
                }
            }

            SoOPPRFRecver recv(workN * d, workN * d * (2 * delta + 1), 1, false, &sock[0]);

            std::vector<block> rand_S(workN * d);

            recv.OPPRF(inputs, rand_S, receiverOnlyReveal && enablePrefilter);

            for (u64 i = 0; i < workN; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_S_j[i] ^= rand_S[i * d + j];
                }
            }

            PEqTSender eqSend(workN, 1, false, &sock[0]);

            eqSend.eq(rand_S_j);
        });

        std::thread recvFilter([&] {
            if (skipReceiverOnlyFilterStage) {
                return;
            }

            std::vector<block> filterKey;
            std::vector<block> filterVal;
            filterKey.reserve(workN * d * (2 * delta + 1));
            filterVal.reserve(workN * d * (2 * delta + 1));

            for (u64 i = 0; i < workN; i++) {
                if (receiverOnlyReveal && enablePrefilter && receiverPrefilterHitMask[i] == 0) {
                    continue;
                }

                for (int j = 0; j < d; j++) {
                    for (int t = -delta; t <= delta; t++) {
                        block key = block(high((*workIdR)[i]) << 8, 0) ^ block(j, (*workRecvSet)[i][j] + t);
                        block val = ZeroBlock;
                        filterKey.push_back(key);
                        filterVal.push_back(val);
                    }
                }
            }

            SoOPPRFSender send(workN * d, workN * d * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> rand_R(workN * d);

            if (receiverOnlyReveal && enablePrefilter) {
                send.OPPRF(filterKey, filterVal, rand_R, filterKey.size());
            } else {
                send.OPPRF(filterKey, filterVal, rand_R);
            }

            for (u64 i = 0; i < workN; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_R_j[i] ^= rand_R[i * d + j];
                }
            }

            PEqTRecver eqRecv(workN, 1, false, &sock[1]);

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
            send.configure(workN, 128);
            send.mMultType = type;

            coproto::sync_wait(send.genSilentBaseOts(prng, sock[0]));

            std::vector<std::array<block, 2>> messages(workN);

            coproto::sync_wait(send.send(messages, prng, sock[0]));

            std::vector<block> correctMessages(workN * d / 2 * 2);
            PRNG prng0, prng1;
            for (u64 i = 0; i < workN; i++) {
                prng0.SetSeed(messages[i][0]);
                prng1.SetSeed(messages[i][1]);
                for (int j = 0; j < d / 2; j++) {
                    correctMessages[i * d + j * 2] = prng0.get<block>();
                    correctMessages[i * d + j * 2 + 1] = block((*workSendSet)[i][j * 2], (*workSendSet)[i][j * 2 + 1]) ^ prng0.get<block>();
                }
            }
            coproto::sync_wait(sock[0].send(correctMessages));
        });

        std::vector<std::vector<block>> matches;

        std::thread recvOT([&] {
            SilentOtExtReceiver recv;
            recv.configure(workN, 128);
            recv.mMultType = type;

            coproto::sync_wait(recv.genSilentBaseOts(prng, sock[1]));

            std::vector<block> messages(workN);
            BitVector choices(choiceBit.data(), choiceBit.size());

            coproto::sync_wait(recv.receive(choices, messages, prng, sock[1]));

            std::vector<block> correctMessages(workN * d / 2 * 2);
            coproto::sync_wait(sock[1].recv(correctMessages));

            PRNG prng;
            for (u64 i = 0; i < workN; i++) {
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
        time.setTimePoint("OT done");

        std::vector<block> senderRevealedIntersectionIds;
        if (mutualReveal) {
            std::thread senderReveal([&] {
                uint64_t count = 0;
                coproto::sync_wait(sock[0].recv(count));
                senderRevealedIntersectionIds.resize(count);
                if (count != 0) {
                    coproto::sync_wait(sock[0].recv(senderRevealedIntersectionIds));
                }
            });

            std::thread receiverReveal([&] {
                std::vector<block> receiverRevealedIntersectionIds;
                receiverRevealedIntersectionIds.reserve(choiceBit.size());
                for (u64 i = 0; i < workN; ++i) {
                    if (choiceBit[i]) {
                        receiverRevealedIntersectionIds.push_back((*workIdR)[i]);
                    }
                }

                const uint64_t count = receiverRevealedIntersectionIds.size();
                coproto::sync_wait(sock[1].send(count));
                if (count != 0) {
                    coproto::sync_wait(sock[1].send(receiverRevealedIntersectionIds));
                }
            });

            senderReveal.join();
            receiverReveal.join();
        }

        stageRun.mark("OT done", totalCommBytes(sock, sock2));

        if (enablePrefilter) {
            std::vector<block> trueMatchedReceiverIds;
            trueMatchedReceiverIds.reserve(choiceBit.size());

            for (u64 i = 0; i < workN; ++i) {
                if (!choiceBit[i]) {
                    continue;
                }

                const uint64_t originalIndex = static_cast<uint64_t>(activeIndices[i]);
                if (trueIntersectionIndexSet.contains(originalIndex)) {
                    trueMatchedReceiverIds.push_back((*workIdR)[i]);
                }
            }

            filterAuditTotals.true_intersection_count += collectDistinctBlocks(trueMatchedReceiverIds).size();
        }

        const uint64_t receiverIntersectionHits = countSelections(choiceBit);
        mutualIntersectionHitsTotal += receiverIntersectionHits;

        if (verbose >= 1) {
            for (int i = 0; i < choiceBit.size(); i++) {
                if (choiceBit[i] && verbose >= 2) {
                    std::cout << "intersection at index " << activeIndices[i] << std::endl;
                }
                if (choiceBit[i] && !trueIntersectionIndexSet.contains(static_cast<uint64_t>(activeIndices[i]))) {
                    throw runtime_error("false positive in fuzzyPsi");
                }
            }
            if (mutualReveal && verbose >= 2) {
                std::cout << "sender reveal mode: " << intersectionRevealModeName(revealMode) << std::endl;
                for (const block &id : senderRevealedIntersectionIds) {
                    std::cout << "sender learns intersection ID " << id << std::endl;
                }
            }
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
    if (mutualReveal) {
        const uint64_t runs = static_cast<uint64_t>(std::max(numTry, 1));
        const double avgMutualIntersectionHits = static_cast<double>(mutualIntersectionHitsTotal) / static_cast<double>(runs);
        std::cout << "[Result] Mutual Intersection Found: "
                  << fpsi::stats::format_summary_count(avgMutualIntersectionHits)
                  << " items." << std::endl;
    }
    printStageDiagnostics(verbose, time, stageSummary);
    if (enablePrefilter) {
        fpsi::stats::print_filter_audit_stats("fpsiFilterLinf", filterAuditTotals, static_cast<uint64_t>(std::max(numTry, 1)));
    } else {
        fpsi::stats::id_filtered_total.store(
            fpsi::stats::id_generated_total.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        fpsi::stats::print_id_stats("fuzzyPsi");
    }
    // std::cout << "comm: " << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB, "
    //   << " time: " << std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000) << " s" << std::endl;
}

void fuzzyPsiLp(const oc::CLP &cmd)
{
    fpsi::stats::reset_id_stats();

    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int lp = cmd.getOr("p", 2);
    int interSize = cmd.getOr("nn", 4);
    int verbose = cmd.getOr("v", 0);
    int numTry = cmd.getOr("try", 1);
    const IntersectionRevealMode revealMode = parseIntersectionRevealMode(cmd);
    const ExecutionPath executionPath = parseExecutionPath(cmd);
    const bool mutualReveal = revealMode == IntersectionRevealMode::Mutual;
    const bool receiverOnlyReveal = revealMode == IntersectionRevealMode::ReceiverOnly;
    const bool useReceiverFuseHandoff = executionPath == ExecutionPath::ReceiverFuseHandoff;

    u64 delta_p = std::pow(delta, lp);
    int prefixLen = static_cast<int>(std::ceil(std::log2(delta_p + 1)));
    const std::string prefilterMode = toLowerCopy(cmd.getOr<std::string>("prefilter", ""));
    const bool prefilterRequested = !prefilterMode.empty();
    const bool enableLegacyPrefilter = prefilterRequested && !useReceiverFuseHandoff;
    const bool enableAnyPrefilterPath = enableLegacyPrefilter || useReceiverFuseHandoff;
    fpsi::prefilter::PrefilterKind prefilterKind = fpsi::prefilter::PrefilterKind::BinaryFuse;
    constexpr double kBinaryFuseHelperFpr = 1e-3;

    if (cmd.isSet("fpr")) {
        throw std::runtime_error("fuzzyPsiLp does not support -fpr; the Binary Fuse prefilter uses a fixed configuration");
    }

    if (prefilterRequested) {
        if (
            prefilterMode == "bfuse" ||
            prefilterMode == "binaryfuse" ||
            prefilterMode == "binary_fuse" ||
            prefilterMode == "binary-fuse" ||
            prefilterMode == "fuse") {
            prefilterKind = fpsi::prefilter::PrefilterKind::BinaryFuse;
        } else {
            throw std::runtime_error("fuzzyPsiLp currently supports only -prefilter bfuse");
        }
    }
    if (mutualReveal && executionPath == ExecutionPath::Legacy && !enableLegacyPrefilter) {
        throw std::runtime_error("mutual reveal mode requires -prefilter bfuse");
    }

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

    std::unordered_set<uint64_t> trueIntersectionIndexSet;
    trueIntersectionIndexSet.reserve(interIndices.size());
    for (u64 idx : interIndices) {
        trueIntersectionIndexSet.insert(static_cast<uint64_t>(idx));
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
    uint64_t prefilterGeneratedAcc = 0;
    uint64_t prefilterFilteredAcc = 0;
    fpsi::stats::FilterAuditStats filterAuditTotals;
    uint64_t mutualIntersectionHitsTotal = 0;

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        StageProfileRun stageRun(stageSummary);
        stageRun.start(totalCommBytes(sock, sock2));
        fpsi::stats::id_used_total.fetch_add(static_cast<uint64_t>(interIndices.size()) * 2, std::memory_order_relaxed);

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

        u64 workN = n;
        std::vector<uint32_t> activeIndices(n);
        std::iota(activeIndices.begin(), activeIndices.end(), 0);
        std::vector<std::vector<u64>> filteredSendSet;
        std::vector<std::vector<u64>> filteredRecvSet;
        std::vector<block> filteredIdS;
        std::vector<block> filteredIdR;
        std::vector<uint8_t> receiverPrefilterHitMask(n, 1);
        bool skipReceiverOnlyFilterStage = false;

        const std::vector<std::vector<u64>> *workSendSet = &sendSet;
        const std::vector<std::vector<u64>> *workRecvSet = &recvSet;
        const std::vector<block> *workIdS = &ID_S;
        const std::vector<block> *workIdR = &ID_R;

        if (enableLegacyPrefilter) {
            const std::vector<block> distinctSenderIds = collectDistinctBlocks(ID_S);
            const std::vector<block> distinctReceiverIds = collectDistinctBlocks(ID_R);
            uint64_t receiverDistinctHits = 0;
            std::vector<uint32_t> receiverKeptIndices;
            std::vector<uint32_t> senderKeptIndices;

            if (receiverOnlyReveal) {
                std::thread sendPrefilter([&] {
                    const auto serializedFilter = fpsi::prefilter::buildSerializedPrefilter(
                        prefilterKind,
                        ID_S,
                        kBinaryFuseHelperFpr);
                    const uint64_t filterBytes = serializedFilter.size();
                    coproto::sync_wait(sock[0].send(filterBytes));
                    coproto::sync_wait(sock[0].send(serializedFilter));
                });

                std::thread recvPrefilter([&] {
                    uint64_t filterBytes = 0;
                    coproto::sync_wait(sock[1].recv(filterBytes));
                    std::vector<uint8_t> serializedFilter(filterBytes);
                    coproto::sync_wait(sock[1].recv(serializedFilter));

                    const auto distinctHitIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        distinctReceiverIds);
                    receiverDistinctHits = distinctHitIndices.size();

                    receiverKeptIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        ID_R);
                    for (uint32_t index : receiverKeptIndices) {
                        receiverPrefilterHitMask[index] = 1;
                    }
                    for (u64 i = 0; i < n; ++i) {
                        if (std::find(receiverKeptIndices.begin(), receiverKeptIndices.end(), static_cast<uint32_t>(i)) == receiverKeptIndices.end()) {
                            receiverPrefilterHitMask[i] = 0;
                        }
                    }
                });

                sendPrefilter.join();
                recvPrefilter.join();
                skipReceiverOnlyFilterStage = receiverKeptIndices.empty();
            } else {
                const block senderPrefilterDummySeed = prng.get<block>();
                std::thread sendPrefilter([&] {
                    PRNG localDummyPrng(senderPrefilterDummySeed);
                    const auto serializedFilter = fpsi::prefilter::buildSerializedPrefilter(
                        prefilterKind,
                        ID_S,
                        kBinaryFuseHelperFpr);
                    const uint64_t filterBytes = serializedFilter.size();
                    coproto::sync_wait(sock[0].send(filterBytes));
                    coproto::sync_wait(sock[0].send(serializedFilter));

                    uint64_t candidateIdCount = 0;
                    coproto::sync_wait(sock[0].recv(candidateIdCount));
                    std::vector<block> receiverCandidateIds(candidateIdCount);
                    if (candidateIdCount != 0) {
                        coproto::sync_wait(sock[0].recv(receiverCandidateIds));
                    }

                    senderKeptIndices = selectIndicesForOrderedIdsWithRandomFallback(
                        receiverCandidateIds,
                        ID_S,
                        localDummyPrng);
                });

                std::thread recvPrefilter([&] {
                    uint64_t filterBytes = 0;
                    coproto::sync_wait(sock[1].recv(filterBytes));
                    std::vector<uint8_t> serializedFilter(filterBytes);
                    coproto::sync_wait(sock[1].recv(serializedFilter));

                    const auto distinctHitIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        distinctReceiverIds);
                    receiverDistinctHits = distinctHitIndices.size();

                    receiverKeptIndices = fpsi::prefilter::querySerializedPrefilter(
                        prefilterKind,
                        serializedFilter,
                        ID_R);

                    const std::vector<block> receiverCandidateIds = selectByIndex(ID_R, receiverKeptIndices);
                    const uint64_t candidateIdCount = receiverCandidateIds.size();
                    coproto::sync_wait(sock[1].send(candidateIdCount));
                    if (candidateIdCount != 0) {
                        coproto::sync_wait(sock[1].send(receiverCandidateIds));
                    }
                });

                sendPrefilter.join();
                recvPrefilter.join();
                filteredSendSet = selectRowsByIndex(sendSet, senderKeptIndices);
                filteredRecvSet = selectRowsByIndex(recvSet, receiverKeptIndices);
                filteredIdS = selectByIndex(ID_S, senderKeptIndices);
                filteredIdR = selectByIndex(ID_R, receiverKeptIndices);
                activeIndices = selectByIndex(activeIndices, receiverKeptIndices);

                workN = filteredIdR.size();
                workSendSet = &filteredSendSet;
                workRecvSet = &filteredRecvSet;
                workIdS = &filteredIdS;
                workIdR = &filteredIdR;
            }

            // These counters are reported in "both parties' IDs", so keep
            // prefilter counts in the same unit as generated/used totals.
            prefilterGeneratedAcc += static_cast<uint64_t>(n) * 2;
            prefilterFilteredAcc += (receiverOnlyReveal ? static_cast<uint64_t>(n) * 2 : workN * 2);
            fpsi::stats::id_generated_total.store(prefilterGeneratedAcc, std::memory_order_relaxed);
            fpsi::stats::id_filtered_total.store(prefilterFilteredAcc, std::memory_order_relaxed);

            filterAuditTotals.s_id_generated_distinct += distinctSenderIds.size();
            filterAuditTotals.r_id_generated_distinct += distinctReceiverIds.size();
            filterAuditTotals.true_intersection_estimate += static_cast<uint64_t>(interIndices.size());
            filterAuditTotals.r_total_hits += receiverDistinctHits;
            filterAuditTotals.r_filtered_useless_ids += static_cast<uint64_t>(distinctReceiverIds.size()) - receiverDistinctHits;
            stageRun.mark("prefilter done", totalCommBytes(sock, sock2));
        } else if (useReceiverFuseHandoff) {
            const std::vector<block> distinctSenderIds = collectDistinctBlocks(ID_S);
            const std::vector<block> distinctReceiverIds = collectDistinctBlocks(ID_R);
            std::vector<uint32_t> senderKeptIndices;

            std::thread senderFuseHandoff([&] {
                uint64_t filterBytes = 0;
                coproto::sync_wait(sock[0].recv(filterBytes));
                std::vector<uint8_t> serializedFilter(filterBytes);
                if (filterBytes != 0) {
                    coproto::sync_wait(sock[0].recv(serializedFilter));
                }

                senderKeptIndices = fpsi::prefilter::querySerializedPrefilter(
                    prefilterKind,
                    serializedFilter,
                    ID_S);

                const uint64_t candidateCount = senderKeptIndices.size();
                coproto::sync_wait(sock[0].send(candidateCount));
                if (candidateCount != 0) {
                    coproto::sync_wait(sock[0].send(senderKeptIndices));
                }

                filteredSendSet = selectRowsByIndex(sendSet, senderKeptIndices);
                filteredIdS = selectByIndex(ID_S, senderKeptIndices);
            });

            std::thread receiverFuseHandoff([&] {
                const auto serializedFilter = fpsi::prefilter::buildSerializedPrefilter(
                    prefilterKind,
                    ID_R,
                    kBinaryFuseHelperFpr);
                const uint64_t filterBytes = serializedFilter.size();
                coproto::sync_wait(sock[1].send(filterBytes));
                if (filterBytes != 0) {
                    coproto::sync_wait(sock[1].send(serializedFilter));
                }

                uint64_t candidateCount = 0;
                coproto::sync_wait(sock[1].recv(candidateCount));
                senderKeptIndices.resize(candidateCount);
                if (candidateCount != 0) {
                    coproto::sync_wait(sock[1].recv(senderKeptIndices));
                }

                filteredRecvSet = selectRowsByIndex(recvSet, senderKeptIndices);
                filteredIdR = selectByIndex(ID_R, senderKeptIndices);
                activeIndices = selectByIndex(activeIndices, senderKeptIndices);
            });

            senderFuseHandoff.join();
            receiverFuseHandoff.join();

            if (filteredIdS.size() != filteredIdR.size()) {
                throw std::runtime_error("receiver_fuse_handoff candidate materialization mismatch");
            }

            workN = filteredIdR.size();
            workSendSet = &filteredSendSet;
            workRecvSet = &filteredRecvSet;
            workIdS = &filteredIdS;
            workIdR = &filteredIdR;

            const uint64_t receiverDistinctHits = collectDistinctBlocks(filteredIdR).size();
            prefilterGeneratedAcc += static_cast<uint64_t>(n) * 2;
            prefilterFilteredAcc += workN * 2;
            fpsi::stats::id_generated_total.store(prefilterGeneratedAcc, std::memory_order_relaxed);
            fpsi::stats::id_filtered_total.store(prefilterFilteredAcc, std::memory_order_relaxed);

            filterAuditTotals.s_id_generated_distinct += distinctSenderIds.size();
            filterAuditTotals.r_id_generated_distinct += distinctReceiverIds.size();
            filterAuditTotals.true_intersection_estimate += static_cast<uint64_t>(interIndices.size());
            filterAuditTotals.r_total_hits += receiverDistinctHits;
            filterAuditTotals.r_filtered_useless_ids += static_cast<uint64_t>(distinctReceiverIds.size()) - receiverDistinctHits;
            stageRun.mark("prefilter done", totalCommBytes(sock, sock2));
        }

        if (workN == 0) {
            time.setTimePoint("filter done");
            stageRun.mark("filter done", totalCommBytes(sock, sock2));
            time.setTimePoint("OT done");
            stageRun.mark("OT done", totalCommBytes(sock, sock2));
            continue;
        }

        std::vector<u8> choiceBit(workN, 0);

        std::vector<u64> disR(workN, 0);
        std::vector<u64> disS(workN, 0);

        std::vector<block> prefixR;
        std::vector<block> prefixS;
        uint64_t filterOprfCommBytes = 0;
        uint64_t filterOkvsCommBytes = 0;
        uint64_t filterB2aCommBytes = 0;
        uint64_t filterPeqtCommBytes = 0;

        std::thread sendFilter([&] {
            if (skipReceiverOnlyFilterStage) {
                return;
            }

            std::vector<block> inputs(workN * d);

            for (u64 i = 0; i < workN; i++) {
                for (int j = 0; j < d; j++) {
                    auto id = (*workIdS)[i];
                    inputs[i * d + j] = block(high(id) << 8, 0) ^ block(j, (*workSendSet)[i][j]); // 8 bits for dimension
                }
            }

            SoOPPRFRecver recv(workN * d, workN * d * (2 * delta + 1), 1, false, &sock[0]);

            std::vector<block> rand_S(workN * d);
            SoOPPRFCommStats soOpprfStats;
            recv.OPPRF(inputs, rand_S, receiverOnlyReveal && enableLegacyPrefilter, soOpprfStats);
            filterOprfCommBytes = soOpprfStats.oprf_comm_bytes;
            filterOkvsCommBytes = soOpprfStats.okvs_comm_bytes;

            std::vector<u64> rand_S_A(workN * d);

            oc::Timer localTime;

            auto s = localTime.setTimePoint("b2a start");

            B2aSender b2aSender(workN * d, &sock[0]);
            const uint64_t b2aCommBefore = sock[0].bytesReceived() + sock[0].bytesSent();
            b2aSender.b2a(rand_S, rand_S_A);
            const uint64_t b2aCommAfter = sock[0].bytesReceived() + sock[0].bytesSent();
            filterB2aCommBytes = b2aCommAfter - b2aCommBefore;

            auto e = localTime.setTimePoint("b2a done");

            for (u64 i = 0; i < workN; i++) {
                for (u64 j = 0; j < d; j++) {
                    disS[i] += rand_S_A[i * d + j];
                }
            }

            for (u64 i = 0; i < workN; i++) {
                auto pre = getIntervalPrefix(0ULL - disS[i], delta_p - disS[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() < (workN * prefixLen)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(workN * prefixLen, 1, false, &sock[0]);

            const uint64_t peqtCommBefore = sock[0].bytesReceived() + sock[0].bytesSent();
            eqSend.eq(prefixS);
            const uint64_t peqtCommAfter = sock[0].bytesReceived() + sock[0].bytesSent();
            filterPeqtCommBytes = peqtCommAfter - peqtCommBefore;
        });

        std::thread recvFilter([&] {
            if (skipReceiverOnlyFilterStage) {
                return;
            }

            std::vector<block> filterKey;
            std::vector<block> filterVal;
            filterKey.reserve(workN * d * (2 * delta + 1));
            filterVal.reserve(workN * d * (2 * delta + 1));

            for (u64 i = 0; i < workN; i++) {
                if (receiverOnlyReveal && enableLegacyPrefilter && receiverPrefilterHitMask[i] == 0) {
                    continue;
                }

                for (int j = 0; j < d; j++) {
                    for (int t = -delta; t <= delta; t++) {
                        auto id = (*workIdR)[i];
                        block key = block(high(id) << 8, 0) ^ block(j, (*workRecvSet)[i][j] + t);
                        block val = block(0, std::pow(std::abs(t), lp));
                        filterKey.push_back(key);
                        filterVal.push_back(val);
                    }
                }
            }

            SoOPPRFSender send(workN * d, workN * d * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> rand_R(workN * d);

            if (receiverOnlyReveal && enableLegacyPrefilter) {
                send.OPPRF(filterKey, filterVal, rand_R, filterKey.size());
            } else {
                send.OPPRF(filterKey, filterVal, rand_R);
            }

            std::vector<u64> rand_R_A(workN * d);

            B2aRecver b2aRecver(workN * d, &sock[1]);
            b2aRecver.b2a(rand_R, rand_R_A);

            for (u64 i = 0; i < workN; i++) {
                for (u64 j = 0; j < d; j++) {
                    disR[i] += rand_R_A[i * d + j];
                }
            }

            for (u64 i = 0; i < workN; i++) {
                auto pre = getPrefix(disR[i], prefixLen);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(workN * prefixLen, 1, false, &sock[1]);

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
            send.configure(workN, 128);
            send.mMultType = type;

            coproto::sync_wait(send.genSilentBaseOts(prng, sock[0]));

            std::vector<std::array<block, 2>> messages(workN);

            coproto::sync_wait(send.send(messages, prng, sock[0]));

            std::vector<block> correctMessages(workN * d / 2 * 2);
            PRNG prng0, prng1;
            for (u64 i = 0; i < workN; i++) {
                prng0.SetSeed(messages[i][0]);
                prng1.SetSeed(messages[i][1]);
                for (int j = 0; j < d / 2; j++) {
                    correctMessages[i * d + j * 2] = prng0.get<block>();
                    correctMessages[i * d + j * 2 + 1] = block((*workSendSet)[i][j * 2], (*workSendSet)[i][j * 2 + 1]) ^ prng0.get<block>();
                }
            }
            coproto::sync_wait(sock[0].send(correctMessages));
        });

        std::vector<std::vector<block>> matches;

        std::thread recvOT([&] {
            SilentOtExtReceiver recv;
            recv.configure(workN, 128);
            recv.mMultType = type;

            coproto::sync_wait(recv.genSilentBaseOts(prng, sock[1]));

            std::vector<block> messages(workN);
            BitVector choices(choiceBit.data(), choiceBit.size());

            coproto::sync_wait(recv.receive(choices, messages, prng, sock[1]));

            std::vector<block> correctMessages(workN * d / 2 * 2);
            coproto::sync_wait(sock[1].recv(correctMessages));

            PRNG prng;
            for (u64 i = 0; i < workN; i++) {
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
        time.setTimePoint("OT done");

        std::vector<block> senderRevealedIntersectionIds;
        if (mutualReveal) {
            std::thread senderReveal([&] {
                uint64_t count = 0;
                coproto::sync_wait(sock[0].recv(count));
                senderRevealedIntersectionIds.resize(count);
                if (count != 0) {
                    coproto::sync_wait(sock[0].recv(senderRevealedIntersectionIds));
                }
            });

            std::thread receiverReveal([&] {
                std::vector<block> receiverRevealedIntersectionIds;
                receiverRevealedIntersectionIds.reserve(choiceBit.size());
                for (u64 i = 0; i < workN; ++i) {
                    if (choiceBit[i]) {
                        receiverRevealedIntersectionIds.push_back((*workIdR)[i]);
                    }
                }

                const uint64_t count = receiverRevealedIntersectionIds.size();
                coproto::sync_wait(sock[1].send(count));
                if (count != 0) {
                    coproto::sync_wait(sock[1].send(receiverRevealedIntersectionIds));
                }
            });

            senderReveal.join();
            receiverReveal.join();
        }

        stageRun.mark("OT done", totalCommBytes(sock, sock2));

        if (enableAnyPrefilterPath) {
            std::vector<block> trueMatchedReceiverIds;
            trueMatchedReceiverIds.reserve(choiceBit.size());

            for (u64 i = 0; i < workN; ++i) {
                if (!choiceBit[i]) {
                    continue;
                }

                const uint64_t originalIndex = static_cast<uint64_t>(activeIndices[i]);
                if (trueIntersectionIndexSet.contains(originalIndex)) {
                    trueMatchedReceiverIds.push_back((*workIdR)[i]);
                }
            }

            filterAuditTotals.true_intersection_count += collectDistinctBlocks(trueMatchedReceiverIds).size();
        }

        const uint64_t receiverIntersectionHits = countSelections(choiceBit);
        mutualIntersectionHitsTotal += receiverIntersectionHits;

        if (verbose >= 1) {
            for (int i = 0; i < choiceBit.size(); i++) {
                if (choiceBit[i] && verbose >= 2) {
                    std::cout << "intersection at index " << activeIndices[i] << std::endl;
                }
                if (choiceBit[i] && !trueIntersectionIndexSet.contains(static_cast<uint64_t>(activeIndices[i]))) {
                    throw runtime_error("false positive in fuzzyPsi");
                }
            }
            if (mutualReveal && verbose >= 2) {
                std::cout << "sender reveal mode: " << intersectionRevealModeName(revealMode) << std::endl;
                for (const block &id : senderRevealedIntersectionIds) {
                    std::cout << "sender learns intersection ID " << id << std::endl;
                }
            }
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
    if (mutualReveal) {
        const uint64_t runs = static_cast<uint64_t>(std::max(numTry, 1));
        const double avgMutualIntersectionHits = static_cast<double>(mutualIntersectionHitsTotal) / static_cast<double>(runs);
        std::cout << "[Result] Mutual Intersection Found: "
                  << fpsi::stats::format_summary_count(avgMutualIntersectionHits)
                  << " items." << std::endl;
    }
    printStageDiagnostics(verbose, time, stageSummary);
    if (enableAnyPrefilterPath) {
        fpsi::stats::print_filter_audit_stats("fpsiFilterLp", filterAuditTotals, static_cast<uint64_t>(std::max(numTry, 1)));
    } else {
        fpsi::stats::id_filtered_total.store(
            fpsi::stats::id_generated_total.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        fpsi::stats::print_id_stats("fuzzyPsiLp");
    }

    // std::cout << "comm: " << (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0 << " MB, "
    //   << " time: " << std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000) << " s" << std::endl;
}
