#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <smmintrin.h>

#include "binaryfusefilter.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "xorfilter.h"

namespace oc = osuCrypto;

namespace {

using Clock = std::chrono::high_resolution_clock;

constexpr uint64_t kSenderSize = 1ULL << 20;
constexpr uint64_t kReceiverSize = 1ULL << 20;
constexpr uint64_t kOverlapSize = 1ULL << 12;
constexpr uint64_t kSeed = 0xC0D1A5E5ULL;
constexpr double kTargetFpr = 1e-3;
constexpr int kRuns = 10;

constexpr uint64_t kHashSeed0 = 0x243F6A8885A308D3ULL;
constexpr uint64_t kHashSeed1 = 0x13198A2E03707344ULL;
constexpr uint64_t kHashSeed2 = 0xA4093822299F31D0ULL;
constexpr uint64_t kHashSeed3 = 0x082EFA98EC4E6C89ULL;
constexpr uint64_t kHashSeed4 = 0x452821E638D01377ULL;

struct BlockWords {
    uint64_t lo = 0;
    uint64_t hi = 0;

    bool operator==(const BlockWords &other) const = default;
};

struct BlockWordsHash {
    size_t operator()(const BlockWords &value) const
    {
        return static_cast<size_t>(value.lo ^ std::rotl(value.hi, 19));
    }
};

struct Dataset {
    std::vector<oc::block> sender_ids;
    std::vector<oc::block> receiver_ids;
    std::vector<uint8_t> receiver_truth_mask;
};

struct RunSample {
    uint64_t size_bytes = 0;
    double build_ms = 0.0;
    double query_mops = 0.0;
    uint64_t fp_count = 0;
    double empirical_fpr_percent = 0.0;
};

struct BenchSummary {
    std::string name;
    uint64_t size_bytes = 0;
    double size_mb = 0.0;
    double bits_per_element = 0.0;
    double build_ms = 0.0;
    double build_ms_range = 0.0;
    double query_mops = 0.0;
    double query_mops_range = 0.0;
    uint64_t fp_count = 0;
    double empirical_fpr_percent = 0.0;
    std::string config_note;
};

BlockWords unpackBlock(const oc::block &value)
{
    return {
        static_cast<uint64_t>(_mm_extract_epi64(value, 0)),
        static_cast<uint64_t>(_mm_extract_epi64(value, 1))
    };
}

uint64_t splitMix64(uint64_t value)
{
    value += 0x9E3779B97F4A7C15ULL;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31);
}

uint64_t hashBlock(const oc::block &value, uint64_t seed)
{
    const BlockWords words = unpackBlock(value);
    const uint64_t lo = splitMix64(words.lo + seed + kHashSeed1);
    const uint64_t hi = splitMix64(words.hi ^ std::rotl(seed + kHashSeed2, 17));
    return splitMix64(lo ^ std::rotl(hi, 29) ^ (words.lo + kHashSeed3) ^ std::rotl(words.hi + kHashSeed4, 7));
}

uint64_t reduce64(uint64_t hash, uint64_t range)
{
    if (range == 0) {
        return 0;
    }

    return static_cast<uint64_t>((static_cast<unsigned __int128>(hash) * range) >> 64);
}

uint16_t fingerprint16(uint64_t hash, uint8_t bits)
{
    const uint16_t mask = bits >= 16 ? std::numeric_limits<uint16_t>::max() : static_cast<uint16_t>((1U << bits) - 1U);
    uint16_t fp = static_cast<uint16_t>(hash & mask);
    if (fp == 0) {
        fp = 1;
    }
    return fp;
}

template <typename T>
void appendScalar(std::vector<uint8_t> &buffer, const T &value)
{
    static_assert(std::is_trivially_copyable_v<T>);
    const auto *ptr = reinterpret_cast<const uint8_t *>(&value);
    buffer.insert(buffer.end(), ptr, ptr + sizeof(T));
}

template <typename T>
T readScalar(const std::vector<uint8_t> &buffer, size_t &offset)
{
    static_assert(std::is_trivially_copyable_v<T>);
    if (offset + sizeof(T) > buffer.size()) {
        throw std::runtime_error("deserialize overflow");
    }

    T value {};
    std::memcpy(&value, buffer.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

Dataset makeDataset()
{
    Dataset dataset;
    dataset.sender_ids.reserve(kSenderSize);
    dataset.receiver_ids.reserve(kReceiverSize);
    dataset.receiver_truth_mask.reserve(kReceiverSize);

    oc::PRNG prng(oc::block(kSeed, kSeed ^ kHashSeed0));
    std::unordered_set<BlockWords, BlockWordsHash> used;
    used.reserve(static_cast<size_t>(kSenderSize + kReceiverSize) * 2);

    auto next_unique_block = [&]() {
        for (;;) {
            const oc::block candidate = prng.get<oc::block>();
            const BlockWords key = unpackBlock(candidate);
            if (used.insert(key).second) {
                return candidate;
            }
        }
    };

    for (uint64_t i = 0; i < kOverlapSize; ++i) {
        const oc::block id = next_unique_block();
        dataset.sender_ids.push_back(id);
        dataset.receiver_ids.push_back(id);
        dataset.receiver_truth_mask.push_back(1);
    }

    while (dataset.sender_ids.size() < kSenderSize) {
        dataset.sender_ids.push_back(next_unique_block());
    }

    while (dataset.receiver_ids.size() < kReceiverSize) {
        dataset.receiver_ids.push_back(next_unique_block());
        dataset.receiver_truth_mask.push_back(0);
    }

    std::mt19937_64 shuffle_rng(kSeed ^ kHashSeed1);
    for (size_t i = dataset.receiver_ids.size(); i > 1; --i) {
        const size_t j = static_cast<size_t>(shuffle_rng() % i);
        std::swap(dataset.receiver_ids[i - 1], dataset.receiver_ids[j]);
        std::swap(dataset.receiver_truth_mask[i - 1], dataset.receiver_truth_mask[j]);
    }

    return dataset;
}

class BloomFilter {
public:
    BloomFilter() = default;

    BloomFilter(const std::vector<oc::block> &keys, double target_fpr)
    {
        const uint64_t item_count = std::max<uint64_t>(1, keys.size());
        const double ln2 = std::log(2.0);
        bit_count_ = static_cast<uint64_t>(std::ceil(-(static_cast<double>(item_count) * std::log(std::max(target_fpr, 1e-9))) / (ln2 * ln2)));
        bit_count_ = std::max<uint64_t>(64, bit_count_);
        num_hashes_ = std::max<uint32_t>(1, static_cast<uint32_t>(std::llround((static_cast<double>(bit_count_) / item_count) * ln2)));
        words_.assign((bit_count_ + 63) / 64, 0);

        for (const auto &key : keys) {
            add(key);
        }
    }

    void add(const oc::block &key)
    {
        const uint64_t h1 = hashBlock(key, kHashSeed0);
        const uint64_t h2 = hashBlock(key, kHashSeed1) | 1ULL;
        for (uint32_t i = 0; i < num_hashes_; ++i) {
            const uint64_t index = (h1 + static_cast<uint64_t>(i) * h2) % bit_count_;
            words_[index >> 6] |= (1ULL << (index & 63));
        }
    }

    bool contains(const oc::block &key) const
    {
        const uint64_t h1 = hashBlock(key, kHashSeed0);
        const uint64_t h2 = hashBlock(key, kHashSeed1) | 1ULL;
        for (uint32_t i = 0; i < num_hashes_; ++i) {
            const uint64_t index = (h1 + static_cast<uint64_t>(i) * h2) % bit_count_;
            if ((words_[index >> 6] & (1ULL << (index & 63))) == 0) {
                return false;
            }
        }
        return true;
    }

    size_t memoryBytes() const
    {
        return sizeof(bit_count_) + sizeof(num_hashes_) + words_.capacity() * sizeof(uint64_t);
    }

    uint32_t numHashes() const
    {
        return num_hashes_;
    }

    uint64_t bitCount() const
    {
        return bit_count_;
    }

private:
    uint64_t bit_count_ = 0;
    uint32_t num_hashes_ = 0;
    std::vector<uint64_t> words_;
};

class VirtualBloomFilter {
public:
    VirtualBloomFilter() = default;

    VirtualBloomFilter(const std::vector<oc::block> &keys, double target_fpr)
    {
        const uint64_t item_count = std::max<uint64_t>(1, keys.size());
        const double ln2 = std::log(2.0);
        const double target_bits = -(static_cast<double>(item_count) * std::log(std::max(target_fpr, 1e-9))) / (ln2 * ln2);

        constexpr uint64_t kTargetItemsPerVirtual = 64;
        virtual_filter_count_ = std::max<uint32_t>(
            1,
            static_cast<uint32_t>((item_count + kTargetItemsPerVirtual - 1) / kTargetItemsPerVirtual));
        bits_per_virtual_ = std::max<uint32_t>(
            64,
            static_cast<uint32_t>(std::ceil((target_bits * 1.10) / static_cast<double>(virtual_filter_count_))));

        const double average_items_per_virtual =
            static_cast<double>(item_count) / static_cast<double>(virtual_filter_count_);
        num_hashes_ = std::max<uint8_t>(
            1,
            static_cast<uint8_t>(std::llround(
                (static_cast<double>(bits_per_virtual_) / std::max(average_items_per_virtual, 1.0)) * ln2)));

        const uint64_t total_bits = static_cast<uint64_t>(virtual_filter_count_) * bits_per_virtual_;
        words_.assign((total_bits + 63) / 64, 0);

        for (const auto &key : keys) {
            add(key);
        }
    }

    void add(const oc::block &key)
    {
        const uint32_t virtual_index = virtualIndexFor(key);
        const uint64_t base = static_cast<uint64_t>(virtual_index) * bits_per_virtual_;
        const uint64_t h1 = hashBlock(key, kHashSeed2);
        const uint64_t h2 = hashBlock(key, kHashSeed3) | 1ULL;
        for (uint8_t i = 0; i < num_hashes_; ++i) {
            const uint64_t local_index = (h1 + static_cast<uint64_t>(i) * h2) % bits_per_virtual_;
            const uint64_t bit_index = base + local_index;
            words_[bit_index >> 6] |= (1ULL << (bit_index & 63));
        }
    }

    bool contains(const oc::block &key) const
    {
        if (virtual_filter_count_ == 0 || bits_per_virtual_ == 0 || words_.empty()) {
            return false;
        }

        const uint32_t virtual_index = virtualIndexFor(key);
        const uint64_t base = static_cast<uint64_t>(virtual_index) * bits_per_virtual_;
        const uint64_t h1 = hashBlock(key, kHashSeed2);
        const uint64_t h2 = hashBlock(key, kHashSeed3) | 1ULL;
        for (uint8_t i = 0; i < num_hashes_; ++i) {
            const uint64_t local_index = (h1 + static_cast<uint64_t>(i) * h2) % bits_per_virtual_;
            const uint64_t bit_index = base + local_index;
            if ((words_[bit_index >> 6] & (1ULL << (bit_index & 63))) == 0) {
                return false;
            }
        }
        return true;
    }

    size_t memoryBytes() const
    {
        return sizeof(virtual_filter_count_) + sizeof(bits_per_virtual_) + sizeof(num_hashes_) + words_.capacity() * sizeof(uint64_t);
    }

    uint32_t virtualFilterCount() const
    {
        return virtual_filter_count_;
    }

    uint32_t bitsPerVirtual() const
    {
        return bits_per_virtual_;
    }

    uint8_t numHashes() const
    {
        return num_hashes_;
    }

private:
    uint32_t virtualIndexFor(const oc::block &key) const
    {
        return static_cast<uint32_t>(reduce64(hashBlock(key, kHashSeed0), virtual_filter_count_));
    }

    uint32_t virtual_filter_count_ = 0;
    uint32_t bits_per_virtual_ = 0;
    uint8_t num_hashes_ = 0;
    std::vector<uint64_t> words_;
};

class CuckooFilter {
public:
    CuckooFilter() = default;

    CuckooFilter(const std::vector<oc::block> &keys, double target_fpr)
    {
        build(keys, target_fpr);
    }

    bool contains(const oc::block &key) const
    {
        if (bucket_count_ == 0) {
            return false;
        }

        const uint16_t fp = fingerprintFor(key);
        const uint32_t index1 = indexFor(key);
        const uint32_t index2 = alternateIndex(index1, fp);
        return bucketContains(index1, fp) || bucketContains(index2, fp);
    }

    size_t memoryBytes() const
    {
        const uint64_t packed_bits =
            static_cast<uint64_t>(bucket_count_) * static_cast<uint64_t>(slots_per_bucket_) * static_cast<uint64_t>(fingerprint_bits_);
        return sizeof(bucket_count_) + sizeof(slots_per_bucket_) + sizeof(fingerprint_bits_) +
            static_cast<size_t>((packed_bits + 7U) / 8U);
    }

    uint32_t bucketCount() const
    {
        return bucket_count_;
    }

    uint8_t slotsPerBucket() const
    {
        return slots_per_bucket_;
    }

    uint8_t fingerprintBits() const
    {
        return fingerprint_bits_;
    }

private:
    static constexpr uint8_t kSlotsPerBucket = 4;
    static constexpr uint32_t kMaxKicks = 500;

    void build(const std::vector<oc::block> &keys, double target_fpr)
    {
        const uint64_t item_count = std::max<uint64_t>(1, keys.size());
        const double fp_bits = std::ceil(std::log2(std::max(2.0 * static_cast<double>(kSlotsPerBucket) / std::max(target_fpr, 1e-9), 2.0)));
        fingerprint_bits_ = static_cast<uint8_t>(std::clamp<double>(fp_bits, 8.0, 16.0));
        slots_per_bucket_ = kSlotsPerBucket;

        const double load = 0.94;
        uint32_t candidate_buckets = static_cast<uint32_t>(
            std::ceil(item_count / (load * static_cast<double>(slots_per_bucket_))));
        candidate_buckets = std::max<uint32_t>(2, candidate_buckets);

        std::mt19937_64 rng(item_count * 17 + static_cast<uint64_t>(fingerprint_bits_) * 13);
        for (;;) {
            bucket_count_ = candidate_buckets;
            buckets_.assign(static_cast<size_t>(bucket_count_) * slots_per_bucket_, 0);
            bool ok = true;
            for (const auto &key : keys) {
                if (!insert(key, rng)) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                return;
            }
            candidate_buckets <<= 1U;
        }
    }

    bool insert(const oc::block &key, std::mt19937_64 &rng)
    {
        uint16_t fp = fingerprintFor(key);
        uint32_t index = indexFor(key);
        uint32_t alt = alternateIndex(index, fp);

        if (insertIntoBucket(index, fp) || insertIntoBucket(alt, fp)) {
            return true;
        }

        std::uniform_int_distribution<uint32_t> bucket_choice(0, 1);
        std::uniform_int_distribution<uint32_t> slot_choice(0, slots_per_bucket_ - 1);

        uint32_t current_index = bucket_choice(rng) == 0 ? index : alt;
        for (uint32_t kick = 0; kick < kMaxKicks; ++kick) {
            const uint32_t slot = slot_choice(rng);
            std::swap(fp, bucketEntry(current_index, slot));
            current_index = alternateIndex(current_index, fp);
            if (insertIntoBucket(current_index, fp)) {
                return true;
            }
        }

        return false;
    }

    uint16_t &bucketEntry(uint32_t bucket, uint32_t slot)
    {
        return buckets_[static_cast<size_t>(bucket) * slots_per_bucket_ + slot];
    }

    const uint16_t &bucketEntry(uint32_t bucket, uint32_t slot) const
    {
        return buckets_[static_cast<size_t>(bucket) * slots_per_bucket_ + slot];
    }

    bool insertIntoBucket(uint32_t bucket, uint16_t fp)
    {
        for (uint32_t slot = 0; slot < slots_per_bucket_; ++slot) {
            uint16_t &entry = bucketEntry(bucket, slot);
            if (entry == 0) {
                entry = fp;
                return true;
            }
        }
        return false;
    }

    bool bucketContains(uint32_t bucket, uint16_t fp) const
    {
        for (uint32_t slot = 0; slot < slots_per_bucket_; ++slot) {
            if (bucketEntry(bucket, slot) == fp) {
                return true;
            }
        }
        return false;
    }

    uint32_t indexFor(const oc::block &key) const
    {
        return static_cast<uint32_t>(reduce64(hashBlock(key, kHashSeed2), bucket_count_));
    }

    uint16_t fingerprintFor(const oc::block &key) const
    {
        return fingerprint16(hashBlock(key, kHashSeed3), fingerprint_bits_);
    }

    uint32_t alternateIndex(uint32_t bucket, uint16_t fp) const
    {
        const uint64_t mixed = splitMix64(static_cast<uint64_t>(fp) * 0x9E3779B97F4A7C15ULL);
        return static_cast<uint32_t>((bucket + reduce64(mixed, bucket_count_)) % bucket_count_);
    }

    uint32_t bucket_count_ = 0;
    uint8_t slots_per_bucket_ = kSlotsPerBucket;
    uint8_t fingerprint_bits_ = 12;
    std::vector<uint16_t> buckets_;
};

class XorFilter {
public:
    XorFilter() = default;

    XorFilter(const std::vector<oc::block> &keys, double target_fpr)
    {
        build(keys, target_fpr);
    }

    bool contains(const oc::block &key) const
    {
        if (filter_.fingerprints == nullptr) {
            return false;
        }
        return xor8_contain(xorKeyForBlock(key), &filter_);
    }

    size_t memoryBytes() const
    {
        return xor8_size_in_bytes(&filter_);
    }

    uint8_t fingerprintBits() const
    {
        return 8;
    }

    uint32_t segmentLength() const
    {
        return static_cast<uint32_t>(filter_.blockLength);
    }

    uint32_t arrayLength() const
    {
        return static_cast<uint32_t>(filter_.blockLength * 3U);
    }

    ~XorFilter()
    {
        xor8_free(&filter_);
    }

    XorFilter(XorFilter &&other) noexcept
        : filter_(other.filter_)
    {
        other.filter_.fingerprints = nullptr;
        other.filter_.seed = 0;
        other.filter_.blockLength = 0;
    }

    XorFilter &operator=(XorFilter &&other) noexcept
    {
        if (this != &other) {
            xor8_free(&filter_);
            filter_ = other.filter_;
            other.filter_.fingerprints = nullptr;
            other.filter_.seed = 0;
            other.filter_.blockLength = 0;
        }
        return *this;
    }

    XorFilter(const XorFilter &) = delete;
    XorFilter &operator=(const XorFilter &) = delete;

private:
    static uint64_t xorKeyForBlock(const oc::block &key)
    {
        return hashBlock(key, kHashSeed1 ^ kHashSeed4);
    }

    void build(const std::vector<oc::block> &keys, double target_fpr)
    {
        (void)target_fpr;

        std::vector<uint64_t> xor_keys(keys.size());
        for (size_t i = 0; i < keys.size(); ++i) {
            xor_keys[i] = xorKeyForBlock(keys[i]);
        }

        if (!xor8_allocate(static_cast<uint32_t>(xor_keys.size()), &filter_)) {
            throw std::runtime_error("xor8 allocation failed");
        }
        if (!xor8_buffered_populate(xor_keys.data(), static_cast<uint32_t>(xor_keys.size()), &filter_)) {
            xor8_free(&filter_);
            throw std::runtime_error("xor8 construction failed");
        }
    }

    xor8_t filter_ {};
};

class BinaryFuseFilter {
public:
    BinaryFuseFilter() = default;

    BinaryFuseFilter(const std::vector<oc::block> &keys, double target_fpr)
    {
        build(keys, target_fpr);
    }

    ~BinaryFuseFilter()
    {
        binary_fuse8_free(&filter_);
    }

    BinaryFuseFilter(BinaryFuseFilter &&other) noexcept
        : filter_(other.filter_)
    {
        other.filter_.Fingerprints = nullptr;
        other.filter_.Seed = 0;
        other.filter_.Size = 0;
        other.filter_.SegmentLength = 0;
        other.filter_.SegmentLengthMask = 0;
        other.filter_.SegmentCount = 0;
        other.filter_.SegmentCountLength = 0;
        other.filter_.ArrayLength = 0;
    }

    BinaryFuseFilter &operator=(BinaryFuseFilter &&other) noexcept
    {
        if (this != &other) {
            binary_fuse8_free(&filter_);
            filter_ = other.filter_;
            other.filter_.Fingerprints = nullptr;
            other.filter_.Seed = 0;
            other.filter_.Size = 0;
            other.filter_.SegmentLength = 0;
            other.filter_.SegmentLengthMask = 0;
            other.filter_.SegmentCount = 0;
            other.filter_.SegmentCountLength = 0;
            other.filter_.ArrayLength = 0;
        }
        return *this;
    }

    BinaryFuseFilter(const BinaryFuseFilter &) = delete;
    BinaryFuseFilter &operator=(const BinaryFuseFilter &) = delete;

    bool contains(const oc::block &key) const
    {
        if (filter_.Fingerprints == nullptr) {
            return false;
        }
        return binary_fuse8_contain(fuseKeyForBlock(key), &filter_);
    }

    size_t memoryBytes() const
    {
        return binary_fuse8_size_in_bytes(&filter_);
    }

    uint32_t arrayLength() const
    {
        return filter_.ArrayLength;
    }

    uint32_t segmentLength() const
    {
        return filter_.SegmentLength;
    }

private:
    static uint64_t fuseKeyForBlock(const oc::block &key)
    {
        return hashBlock(key, kHashSeed0 ^ kHashSeed4);
    }

    void build(const std::vector<oc::block> &keys, double target_fpr)
    {
        (void)target_fpr;

        std::vector<uint64_t> fuse_keys(keys.size());
        for (size_t i = 0; i < keys.size(); ++i) {
            fuse_keys[i] = fuseKeyForBlock(keys[i]);
        }

        if (!binary_fuse8_allocate(static_cast<uint32_t>(fuse_keys.size()), &filter_)) {
            throw std::runtime_error("binary fuse filter allocation failed");
        }
        if (!binary_fuse8_populate(fuse_keys.data(), static_cast<uint32_t>(fuse_keys.size()), &filter_)) {
            binary_fuse8_free(&filter_);
            throw std::runtime_error("binary fuse filter construction failed");
        }
    }

    binary_fuse8_t filter_ {};
};

template <typename T>
double medianOf(std::vector<T> values)
{
    std::sort(values.begin(), values.end());
    const size_t n = values.size();
    if (n == 0) {
        return 0.0;
    }
    if ((n & 1U) == 1U) {
        return static_cast<double>(values[n / 2]);
    }
    return (static_cast<double>(values[n / 2 - 1]) + static_cast<double>(values[n / 2])) / 2.0;
}

template <typename T>
double rangeOf(const std::vector<T> &values)
{
    if (values.empty()) {
        return 0.0;
    }
    const auto [min_it, max_it] = std::minmax_element(values.begin(), values.end());
    return static_cast<double>(*max_it) - static_cast<double>(*min_it);
}

double bytesToMb(uint64_t bytes)
{
    return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

std::string formatDouble(double value, int precision)
{
    std::ostringstream out;
    out << std::fixed << std::setprecision(precision) << value;
    return out.str();
}

template <typename Filter, typename DescribeFn>
BenchSummary benchmarkFilter(
    const std::string &name,
    const Dataset &dataset,
    double target_fpr,
    DescribeFn describe)
{
    std::vector<RunSample> runs;
    runs.reserve(kRuns);
    std::optional<std::string> config_note;

    for (int run = 0; run < kRuns; ++run) {
        const auto build_begin = Clock::now();
        Filter filter(dataset.sender_ids, target_fpr);
        const auto build_end = Clock::now();

        if (!config_note.has_value()) {
            config_note = describe(filter);
        }

        uint64_t false_positives = 0;
        const auto query_begin = Clock::now();
        for (size_t i = 0; i < dataset.receiver_ids.size(); ++i) {
            if (filter.contains(dataset.receiver_ids[i]) && dataset.receiver_truth_mask[i] == 0) {
                ++false_positives;
            }
        }
        const auto query_end = Clock::now();

        const double build_ms =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(build_end - build_begin).count()) / 1e6;
        const double query_seconds =
            static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(query_end - query_begin).count()) / 1e9;
        const double query_mops = query_seconds <= 0.0 ? 0.0 : static_cast<double>(dataset.receiver_ids.size()) / (query_seconds * 1e6);
        const double empirical_fpr_percent =
            (static_cast<double>(false_positives) / static_cast<double>(dataset.receiver_ids.size() - kOverlapSize)) * 100.0;

        runs.push_back({
            static_cast<uint64_t>(filter.memoryBytes()),
            build_ms,
            query_mops,
            false_positives,
            empirical_fpr_percent
        });
    }

    std::vector<uint64_t> size_bytes;
    std::vector<double> build_ms;
    std::vector<double> query_mops;
    std::vector<uint64_t> fp_count;
    std::vector<double> empirical_fpr_percent;
    for (const auto &run : runs) {
        size_bytes.push_back(run.size_bytes);
        build_ms.push_back(run.build_ms);
        query_mops.push_back(run.query_mops);
        fp_count.push_back(run.fp_count);
        empirical_fpr_percent.push_back(run.empirical_fpr_percent);
    }

    BenchSummary summary;
    summary.name = name;
    summary.size_bytes = static_cast<uint64_t>(std::llround(medianOf(size_bytes)));
    summary.size_mb = bytesToMb(summary.size_bytes);
    summary.bits_per_element = (static_cast<double>(summary.size_bytes) * 8.0) / static_cast<double>(kSenderSize);
    summary.build_ms = medianOf(build_ms);
    summary.build_ms_range = rangeOf(build_ms);
    summary.query_mops = medianOf(query_mops);
    summary.query_mops_range = rangeOf(query_mops);
    summary.fp_count = static_cast<uint64_t>(std::llround(medianOf(fp_count)));
    summary.empirical_fpr_percent = medianOf(empirical_fpr_percent);
    summary.config_note = config_note.value_or("");
    return summary;
}

void writeCsv(const std::vector<BenchSummary> &results)
{
    std::ofstream out("bench_results.csv");
    if (!out) {
        throw std::runtime_error("failed to open bench_results.csv");
    }

    out << "filter_name,size_bytes,bits_per_elem,build_ms,query_mops,fp_count,empirical_fpr\n";
    for (const auto &result : results) {
        out << result.name << ','
            << result.size_bytes << ','
            << formatDouble(result.bits_per_element, 3) << ','
            << formatDouble(result.build_ms, 3) << ','
            << formatDouble(result.query_mops, 3) << ','
            << result.fp_count << ','
            << formatDouble(result.empirical_fpr_percent, 6) << '\n';
    }
}

void writeLatex(const std::vector<BenchSummary> &results)
{
    std::ofstream out("bench_table.tex");
    if (!out) {
        throw std::runtime_error("failed to open bench_table.tex");
    }

    out << "\\begin{table}[t]\n";
    out << "\\centering\n";
    out << "\\small\n";
    out << "\\caption{公平对比结果（|S|=|R|=2^20, 交集=4096, 目标 FPR 0.1\\%，实际 FPR 见脚注）}\n";
    out << "\\label{tab:fair}\n";
    out << "\\begin{tabular}{lrrrrr}\n";
    out << "\\toprule\n";
    out << "Filter Type & Size (MB) & Bits/Element & Build (ms) & Query (MOPS) & Emp. FPR (\\%) \\\\\n";
    out << "\\midrule\n";
    for (const auto &result : results) {
        out << result.name << " & "
            << formatDouble(result.size_mb, 3) << " & "
            << formatDouble(result.bits_per_element, 2) << " & "
            << formatDouble(result.build_ms, 3) << " & "
            << formatDouble(result.query_mops, 3) << " & "
            << formatDouble(result.empirical_fpr_percent, 4) << " \\\\\n";
    }
    out << "\\bottomrule\n";
    out << "\\end{tabular}\n";
    out << "\\footnotesize\n";
    out << "注释：所有结果均为单线程、固定种子、10 次完整构建+查询的中位数。";
    for (size_t i = 0; i < results.size(); ++i) {
        if (i != 0) {
            out << ' ';
        }
        out << results[i].name << "：" << results[i].config_note << "。";
    }
    out << " 当前项目实现仅提供单一 Virtual Bloom、单一 Cuckoo 以及基于 FastFilter 单头库的 xor8 / binary\\_fuse8 版本；";
    out << "XOR 与 Binary Fuse 的理论 FPR 为 1/256\\approx0.39\\%，因此其经验 FPR 不直接对齐 0.1\\% 目标，应结合空间效率一并解读。";
    out << "\\end{table}\n";
}

} // namespace

int main()
{
    try {
        const Dataset dataset = makeDataset();

        std::vector<BenchSummary> results;
        results.reserve(5);

        results.push_back(benchmarkFilter<BloomFilter>(
            "Bloom Filter",
            dataset,
            kTargetFpr,
            [](const BloomFilter &filter) {
                std::ostringstream note;
                note << "按目标 FPR=0.1\\% 自动计算，bit count=" << filter.bitCount()
                     << ", k=" << filter.numHashes()
                     << ", 理论 FPR 接近 0.1\\%";
                return note.str();
            }));

        results.push_back(benchmarkFilter<VirtualBloomFilter>(
            "Virtual Bloom Filter",
            dataset,
            kTargetFpr,
            [](const VirtualBloomFilter &filter) {
                std::ostringstream note;
                note << "virtual filters=" << filter.virtualFilterCount()
                     << ", bits/virtual=" << filter.bitsPerVirtual()
                     << ", k=" << static_cast<uint32_t>(filter.numHashes())
                     << ", 内部按目标 FPR 额外放大约 10\\% 空间";
                return note.str();
            }));

        results.push_back(benchmarkFilter<CuckooFilter>(
            "Cuckoo Filter",
            dataset,
            kTargetFpr,
            [](const CuckooFilter &filter) {
                std::ostringstream note;
                note << "4-slot buckets, fingerprint=" << static_cast<uint32_t>(filter.fingerprintBits())
                     << " bits, buckets=" << filter.bucketCount()
                     << ", 实现内固定目标 load≈0.94, 理论 FPR≈2/2^" << static_cast<uint32_t>(filter.fingerprintBits());
                return note.str();
            }));

        results.push_back(benchmarkFilter<XorFilter>(
            "XOR Filter",
            dataset,
            kTargetFpr,
            [](const XorFilter &filter) {
                std::ostringstream note;
                note << "fingerprint=" << static_cast<uint32_t>(filter.fingerprintBits())
                     << " bits, array length=" << filter.arrayLength()
                     << ", 实际容量系数≈" << formatDouble(static_cast<double>(filter.arrayLength()) / static_cast<double>(kSenderSize), 3)
                     << ", 理论 FPR≈1/2^" << static_cast<uint32_t>(filter.fingerprintBits());
                return note.str();
            }));

        results.push_back(benchmarkFilter<BinaryFuseFilter>(
            "Binary Fuse Filter",
            dataset,
            kTargetFpr,
            [](const BinaryFuseFilter &filter) {
                std::ostringstream note;
                note << "当前项目绑定 binary\\_fuse8, fingerprint=8 bits, array length=" << filter.arrayLength()
                     << ", 实际容量系数≈" << formatDouble(static_cast<double>(filter.arrayLength()) / static_cast<double>(kSenderSize), 3)
                     << ", 理论 FPR≈1/2^8";
                return note.str();
            }));

        writeCsv(results);
        writeLatex(results);

        std::cout << "Generated bench_results.csv and bench_table.tex" << std::endl;
        for (const auto &result : results) {
            std::cout << result.name
                      << " size_bytes=" << result.size_bytes
                      << " bits/elem=" << formatDouble(result.bits_per_element, 3)
                      << " build_ms=" << formatDouble(result.build_ms, 3)
                      << " query_mops=" << formatDouble(result.query_mops, 3)
                      << " fp_count=" << result.fp_count
                      << " empirical_fpr=" << formatDouble(result.empirical_fpr_percent, 6)
                      << std::endl;
        }
        return EXIT_SUCCESS;
    } catch (const std::exception &ex) {
        std::cerr << "fair_prefilter_bench failed: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
}
