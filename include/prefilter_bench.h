#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cryptoTools/Common/block.h"

namespace fpsi::prefilter {

enum class PrefilterKind {
    Bloom,
    Cuckoo,
    Xor
};

struct PrefilterBenchConfig {
    uint64_t receiver_candidate_count = 32768;
    uint64_t ground_truth = 28;
    uint64_t seed = 0;
    double target_fpr = 1e-3;
    uint64_t try_count = 1;
    std::string filter = "all";
};

struct PrefilterDataset {
    std::vector<osuCrypto::block> sender_ids;
    std::vector<osuCrypto::block> receiver_ids;
    std::vector<uint8_t> receiver_truth_mask;
};

struct PrefilterBenchResult {
    std::string name;
    double build_time_us = 0.0;
    double serialized_size_bytes = 0.0;
    double query_time_us = 0.0;
    double id_generated_total = 0.0;
    double id_filtered_total = 0.0;
    double id_used_total = 0.0;
    double redundancy_rate = 0.0;
    double false_positives = 0.0;
    double ground_truth = 0.0;
};

std::string prefilterKindName(PrefilterKind kind);

std::vector<PrefilterKind> parsePrefilterSelection(const std::string &filter_arg);

PrefilterDataset generatePrefilterDataset(uint64_t receiver_candidate_count, uint64_t ground_truth, uint64_t seed);

std::vector<uint8_t> buildSerializedPrefilter(
    PrefilterKind kind,
    const std::vector<osuCrypto::block> &sender_ids,
    double target_fpr);

std::vector<uint32_t> querySerializedPrefilter(
    PrefilterKind kind,
    const std::vector<uint8_t> &serialized_filter,
    const std::vector<osuCrypto::block> &receiver_ids);

std::vector<PrefilterBenchResult> runPrefilterBenchmarks(const PrefilterBenchConfig &config);

void printPrefilterBenchMarkdown(
    const std::vector<PrefilterBenchResult> &results,
    const PrefilterBenchConfig &config);

} // namespace fpsi::prefilter
