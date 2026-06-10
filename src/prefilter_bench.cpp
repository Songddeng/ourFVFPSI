#include "prefilter_bench.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

#include <smmintrin.h>

#include "cryptoTools/Crypto/PRNG.h"
#include "id_stats.h"

namespace oc = osuCrypto;

namespace fpsi::prefilter {

namespace {

using Clock = std::chrono::steady_clock;

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

std::string toLowerCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
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
        throw std::runtime_error("prefilter deserialize overflow");
    }

    T value {};
    std::memcpy(&value, buffer.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

std::string formatCount(double value)
{
    std::ostringstream out;
    const double rounded = std::round(value);
    if (std::abs(value - rounded) < 1e-9) {
        out << static_cast<uint64_t>(rounded);
        return out.str();
    }

    out << std::fixed << std::setprecision(2) << value;
    return out.str();
}

std::string formatTime(double time_us)
{
    std::ostringstream out;
    if (time_us >= 1000.0) {
        out << std::fixed << std::setprecision(3) << (time_us / 1000.0) << " ms";
    } else {
        out << std::fixed << std::setprecision(1) << time_us << " us";
    }
    return out.str();
}

std::string formatBytes(double bytes)
{
    std::ostringstream out;
    if (bytes >= 1024.0) {
        out << std::fixed << std::setprecision(2) << (bytes / 1024.0) << " KB";
    } else {
        out << std::fixed << std::setprecision(0) << bytes << " B";
    }
    return out.str();
}

std::string formatRate(double rate)
{
    std::ostringstream out;
    out << std::fixed << std::setprecision(6) << rate << " (" << std::setprecision(2) << rate * 100.0 << "%)";
    return out.str();
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

    std::vector<uint8_t> serialize() const
    {
        std::vector<uint8_t> buffer;
        buffer.reserve(sizeof(bit_count_) + sizeof(num_hashes_) + words_.size() * sizeof(uint64_t));
        appendScalar(buffer, bit_count_);
        appendScalar(buffer, num_hashes_);
        appendScalar(buffer, static_cast<uint64_t>(words_.size()));
        for (uint64_t word : words_) {
            appendScalar(buffer, word);
        }
        return buffer;
    }

    static BloomFilter deserialize(const std::vector<uint8_t> &buffer)
    {
        size_t offset = 0;
        BloomFilter filter;
        filter.bit_count_ = readScalar<uint64_t>(buffer, offset);
        filter.num_hashes_ = readScalar<uint32_t>(buffer, offset);
        const uint64_t word_count = readScalar<uint64_t>(buffer, offset);
        filter.words_.resize(word_count);
        for (uint64_t &word : filter.words_) {
            word = readScalar<uint64_t>(buffer, offset);
        }
        return filter;
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

    std::vector<uint8_t> serialize() const
    {
        std::vector<uint8_t> buffer;
        buffer.reserve(
            sizeof(virtual_filter_count_) +
            sizeof(bits_per_virtual_) +
            sizeof(num_hashes_) +
            sizeof(uint64_t) +
            words_.size() * sizeof(uint64_t));
        appendScalar(buffer, virtual_filter_count_);
        appendScalar(buffer, bits_per_virtual_);
        appendScalar(buffer, num_hashes_);
        appendScalar(buffer, static_cast<uint64_t>(words_.size()));
        for (uint64_t word : words_) {
            appendScalar(buffer, word);
        }
        return buffer;
    }

    static VirtualBloomFilter deserialize(const std::vector<uint8_t> &buffer)
    {
        size_t offset = 0;
        VirtualBloomFilter filter;
        filter.virtual_filter_count_ = readScalar<uint32_t>(buffer, offset);
        filter.bits_per_virtual_ = readScalar<uint32_t>(buffer, offset);
        filter.num_hashes_ = readScalar<uint8_t>(buffer, offset);
        const uint64_t word_count = readScalar<uint64_t>(buffer, offset);
        filter.words_.resize(word_count);
        for (uint64_t &word : filter.words_) {
            word = readScalar<uint64_t>(buffer, offset);
        }
        return filter;
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

    std::vector<uint8_t> serialize() const
    {
        std::vector<uint8_t> buffer;
        buffer.reserve(sizeof(bucket_count_) + sizeof(slots_per_bucket_) + sizeof(fingerprint_bits_) + buckets_.size() * sizeof(uint16_t));
        appendScalar(buffer, bucket_count_);
        appendScalar(buffer, slots_per_bucket_);
        appendScalar(buffer, fingerprint_bits_);
        appendScalar(buffer, static_cast<uint64_t>(buckets_.size()));
        for (uint16_t value : buckets_) {
            appendScalar(buffer, value);
        }
        return buffer;
    }

    static CuckooFilter deserialize(const std::vector<uint8_t> &buffer)
    {
        size_t offset = 0;
        CuckooFilter filter;
        filter.bucket_count_ = readScalar<uint32_t>(buffer, offset);
        filter.slots_per_bucket_ = readScalar<uint8_t>(buffer, offset);
        filter.fingerprint_bits_ = readScalar<uint8_t>(buffer, offset);
        const uint64_t bucket_size = readScalar<uint64_t>(buffer, offset);
        filter.buckets_.resize(bucket_size);
        for (uint16_t &entry : filter.buckets_) {
            entry = readScalar<uint16_t>(buffer, offset);
        }
        return filter;
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

        uint32_t candidate_buckets = 1;
        const double load = 0.95;
        const uint64_t min_buckets = static_cast<uint64_t>(std::ceil(item_count / (load * static_cast<double>(slots_per_bucket_))));
        while (candidate_buckets < min_buckets) {
            candidate_buckets <<= 1U;
        }

        std::mt19937_64 rng(item_count * 17 + static_cast<uint64_t>(fingerprint_bits_) * 13);
        for (;;) {
            bucket_count_ = std::max<uint32_t>(2, candidate_buckets);
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
        return static_cast<uint32_t>(hashBlock(key, kHashSeed2) & (bucket_count_ - 1U));
    }

    uint16_t fingerprintFor(const oc::block &key) const
    {
        return fingerprint16(hashBlock(key, kHashSeed3), fingerprint_bits_);
    }

    uint32_t alternateIndex(uint32_t bucket, uint16_t fp) const
    {
        const uint64_t mixed = splitMix64(static_cast<uint64_t>(fp) * 0x9E3779B97F4A7C15ULL);
        return static_cast<uint32_t>((bucket ^ mixed) & (bucket_count_ - 1U));
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
        if (fingerprints_.empty()) {
            return false;
        }

        const uint64_t hash = hashBlock(key, seed_);
        const auto positions = positionsFor(hash);
        const uint16_t fp = static_cast<uint16_t>(fingerprints_[positions[0]] ^ fingerprints_[positions[1]] ^ fingerprints_[positions[2]]);
        return fp == fingerprintFor(hash);
    }

    std::vector<uint8_t> serialize() const
    {
        std::vector<uint8_t> buffer;
        buffer.reserve(sizeof(seed_) + sizeof(segment_length_) + sizeof(fingerprint_bits_) + fingerprints_.size() * sizeof(uint16_t));
        appendScalar(buffer, seed_);
        appendScalar(buffer, segment_length_);
        appendScalar(buffer, fingerprint_bits_);
        appendScalar(buffer, static_cast<uint64_t>(fingerprints_.size()));
        for (uint16_t fp : fingerprints_) {
            appendScalar(buffer, fp);
        }
        return buffer;
    }

    static XorFilter deserialize(const std::vector<uint8_t> &buffer)
    {
        size_t offset = 0;
        XorFilter filter;
        filter.seed_ = readScalar<uint64_t>(buffer, offset);
        filter.segment_length_ = readScalar<uint32_t>(buffer, offset);
        filter.fingerprint_bits_ = readScalar<uint8_t>(buffer, offset);
        const uint64_t fp_size = readScalar<uint64_t>(buffer, offset);
        filter.fingerprints_.resize(fp_size);
        for (uint16_t &fp : filter.fingerprints_) {
            fp = readScalar<uint16_t>(buffer, offset);
        }
        return filter;
    }

private:
    struct PeelNode {
        uint32_t index = 0;
        uint64_t hash = 0;
    };

    void build(const std::vector<oc::block> &keys, double target_fpr)
    {
        const uint64_t item_count = std::max<uint64_t>(1, keys.size());
        fingerprint_bits_ = static_cast<uint8_t>(std::clamp<double>(std::ceil(std::log2(1.0 / std::max(target_fpr, 1e-9))), 8.0, 16.0));
        uint32_t capacity = 32;
        const uint32_t target = static_cast<uint32_t>(std::ceil(item_count * 1.23));
        while (capacity < target) {
            capacity <<= 1U;
        }
        segment_length_ = std::max<uint32_t>(32, capacity / 3U);
        segment_length_ = 1U << static_cast<uint32_t>(std::ceil(std::log2(static_cast<double>(segment_length_))));

        std::vector<uint64_t> hashes(keys.size());
        for (uint32_t attempt = 0; attempt < 32; ++attempt) {
            seed_ = splitMix64(kHashSeed4 + attempt * 0x9E3779B97F4A7C15ULL + item_count);
            for (size_t i = 0; i < keys.size(); ++i) {
                hashes[i] = hashBlock(keys[i], seed_);
            }
            if (tryBuild(hashes)) {
                return;
            }
            segment_length_ <<= 1U;
        }

        throw std::runtime_error("xor filter construction failed");
    }

    bool tryBuild(const std::vector<uint64_t> &hashes)
    {
        const uint32_t array_length = segment_length_ * 3U;
        std::vector<uint32_t> counts(array_length, 0);
        std::vector<uint64_t> xors(array_length, 0);
        std::deque<uint32_t> queue;
        std::vector<PeelNode> order;
        order.reserve(hashes.size());

        for (uint64_t hash : hashes) {
            const auto pos = positionsFor(hash);
            for (uint32_t index : pos) {
                ++counts[index];
                xors[index] ^= hash;
            }
        }

        for (uint32_t index = 0; index < array_length; ++index) {
            if (counts[index] == 1) {
                queue.push_back(index);
            }
        }

        while (!queue.empty()) {
            const uint32_t index = queue.front();
            queue.pop_front();
            if (counts[index] != 1) {
                continue;
            }

            const uint64_t hash = xors[index];
            const auto pos = positionsFor(hash);
            order.push_back({ index, hash });
            for (uint32_t other : pos) {
                if (counts[other] == 0) {
                    continue;
                }
                --counts[other];
                xors[other] ^= hash;
                if (counts[other] == 1) {
                    queue.push_back(other);
                }
            }
        }

        if (order.size() != hashes.size()) {
            return false;
        }

        fingerprints_.assign(array_length, 0);
        for (auto iter = order.rbegin(); iter != order.rend(); ++iter) {
            const auto pos = positionsFor(iter->hash);
            const uint16_t fp = fingerprintFor(iter->hash);
            if (iter->index == pos[0]) {
                fingerprints_[pos[0]] = static_cast<uint16_t>(fp ^ fingerprints_[pos[1]] ^ fingerprints_[pos[2]]);
            } else if (iter->index == pos[1]) {
                fingerprints_[pos[1]] = static_cast<uint16_t>(fp ^ fingerprints_[pos[0]] ^ fingerprints_[pos[2]]);
            } else {
                fingerprints_[pos[2]] = static_cast<uint16_t>(fp ^ fingerprints_[pos[0]] ^ fingerprints_[pos[1]]);
            }
        }

        return true;
    }

    uint16_t fingerprintFor(uint64_t hash) const
    {
        return fingerprint16(hash, fingerprint_bits_);
    }

    std::array<uint32_t, 3> positionsFor(uint64_t hash) const
    {
        return {
            static_cast<uint32_t>(reduce64(hash, segment_length_)),
            static_cast<uint32_t>(segment_length_ + reduce64(std::rotl(hash, 21), segment_length_)),
            static_cast<uint32_t>(2U * segment_length_ + reduce64(std::rotl(hash, 42), segment_length_))
        };
    }

    uint64_t seed_ = 0;
    uint32_t segment_length_ = 0;
    uint8_t fingerprint_bits_ = 8;
    std::vector<uint16_t> fingerprints_;
};

template <typename Builder, typename Reader>
PrefilterBenchResult runBenchCase(
    std::string name,
    const PrefilterDataset &dataset,
    double target_fpr,
    Builder &&builder,
    Reader &&reader)
{
    fpsi::stats::reset_id_stats();
    fpsi::stats::id_generated_total.store(dataset.receiver_ids.size(), std::memory_order_relaxed);

    const auto build_begin = Clock::now();
    auto filter = builder(dataset.sender_ids, target_fpr);
    const auto build_end = Clock::now();

    const std::vector<uint8_t> serialized = filter.serialize();

    const auto query_begin = Clock::now();
    auto received = reader(serialized);
    uint64_t retained = 0;
    uint64_t used = 0;
    uint64_t false_positives = 0;
    for (size_t i = 0; i < dataset.receiver_ids.size(); ++i) {
        if (received.contains(dataset.receiver_ids[i])) {
            ++retained;
            if (dataset.receiver_truth_mask[i] == 0) {
                ++false_positives;
            } else {
                ++used;
            }
        }
    }
    const auto query_end = Clock::now();

    fpsi::stats::id_filtered_total.store(retained, std::memory_order_relaxed);
    fpsi::stats::id_used_total.store(used, std::memory_order_relaxed);

    PrefilterBenchResult result;
    result.name = std::move(name);
    result.build_time_us = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(build_end - build_begin).count());
    result.serialized_size_bytes = static_cast<double>(serialized.size());
    result.query_time_us = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(query_end - query_begin).count());
    result.id_generated_total = static_cast<double>(fpsi::stats::id_generated_total.load(std::memory_order_relaxed));
    result.id_filtered_total = static_cast<double>(fpsi::stats::id_filtered_total.load(std::memory_order_relaxed));
    result.id_used_total = static_cast<double>(fpsi::stats::id_used_total.load(std::memory_order_relaxed));
    result.false_positives = static_cast<double>(false_positives);
    result.ground_truth = static_cast<double>(std::count(dataset.receiver_truth_mask.begin(), dataset.receiver_truth_mask.end(), static_cast<uint8_t>(1)));
    result.redundancy_rate = result.id_used_total == 0.0 ? 0.0 : (result.id_filtered_total - result.id_used_total) / result.id_used_total;
    return result;
}

PrefilterBenchResult runBenchCase(PrefilterKind kind, const PrefilterDataset &dataset, double target_fpr)
{
    switch (kind) {
    case PrefilterKind::Bloom:
        return runBenchCase(
            prefilterKindName(kind),
            dataset,
            target_fpr,
            [](const std::vector<oc::block> &sender_ids, double fpr) { return BloomFilter(sender_ids, fpr); },
            [](const std::vector<uint8_t> &serialized) { return BloomFilter::deserialize(serialized); });
    case PrefilterKind::VirtualBloom:
        return runBenchCase(
            prefilterKindName(kind),
            dataset,
            target_fpr,
            [](const std::vector<oc::block> &sender_ids, double fpr) { return VirtualBloomFilter(sender_ids, fpr); },
            [](const std::vector<uint8_t> &serialized) { return VirtualBloomFilter::deserialize(serialized); });
    case PrefilterKind::Cuckoo:
        return runBenchCase(
            prefilterKindName(kind),
            dataset,
            target_fpr,
            [](const std::vector<oc::block> &sender_ids, double fpr) { return CuckooFilter(sender_ids, fpr); },
            [](const std::vector<uint8_t> &serialized) { return CuckooFilter::deserialize(serialized); });
    case PrefilterKind::Xor:
        return runBenchCase(
            prefilterKindName(kind),
            dataset,
            target_fpr,
            [](const std::vector<oc::block> &sender_ids, double fpr) { return XorFilter(sender_ids, fpr); },
            [](const std::vector<uint8_t> &serialized) { return XorFilter::deserialize(serialized); });
    }

    throw std::runtime_error("unsupported prefilter kind");
}

struct ResultAccumulator {
    PrefilterBenchResult sum;
    uint64_t count = 0;

    void add(const PrefilterBenchResult &value)
    {
        if (count == 0) {
            sum.name = value.name;
        }
        sum.build_time_us += value.build_time_us;
        sum.serialized_size_bytes += value.serialized_size_bytes;
        sum.query_time_us += value.query_time_us;
        sum.id_generated_total += value.id_generated_total;
        sum.id_filtered_total += value.id_filtered_total;
        sum.id_used_total += value.id_used_total;
        sum.redundancy_rate += value.redundancy_rate;
        sum.false_positives += value.false_positives;
        sum.ground_truth += value.ground_truth;
        ++count;
    }

    PrefilterBenchResult average() const
    {
        PrefilterBenchResult avg = sum;
        const double denom = static_cast<double>(std::max<uint64_t>(count, 1));
        avg.build_time_us /= denom;
        avg.serialized_size_bytes /= denom;
        avg.query_time_us /= denom;
        avg.id_generated_total /= denom;
        avg.id_filtered_total /= denom;
        avg.id_used_total /= denom;
        avg.redundancy_rate /= denom;
        avg.false_positives /= denom;
        avg.ground_truth /= denom;
        return avg;
    }
};

} // namespace

std::string prefilterKindName(PrefilterKind kind)
{
    switch (kind) {
    case PrefilterKind::Bloom:
        return "Bloom Filter";
    case PrefilterKind::VirtualBloom:
        return "Virtual Bloom Filter";
    case PrefilterKind::Cuckoo:
        return "Cuckoo Filter";
    case PrefilterKind::Xor:
        return "XOR Filter";
    }

    throw std::runtime_error("unknown prefilter kind");
}

std::vector<PrefilterKind> parsePrefilterSelection(const std::string &filter_arg)
{
    const std::string lowered = toLowerCopy(filter_arg);
    if (lowered.empty() || lowered == "all") {
        return { PrefilterKind::Bloom, PrefilterKind::VirtualBloom, PrefilterKind::Cuckoo, PrefilterKind::Xor };
    }
    if (lowered == "bloom") {
        return { PrefilterKind::Bloom };
    }
    if (lowered == "vbf" || lowered == "virtual" || lowered == "virtual_bloom" || lowered == "virtual-bloom") {
        return { PrefilterKind::VirtualBloom };
    }
    if (lowered == "cuckoo") {
        return { PrefilterKind::Cuckoo };
    }
    if (lowered == "xor") {
        return { PrefilterKind::Xor };
    }

    throw std::runtime_error("invalid -filter value, expected bloom|vbf|cuckoo|xor|all");
}

PrefilterDataset generatePrefilterDataset(uint64_t receiver_candidate_count, uint64_t ground_truth, uint64_t seed)
{
    PrefilterDataset dataset;
    dataset.receiver_ids.reserve(receiver_candidate_count);
    dataset.receiver_truth_mask.reserve(receiver_candidate_count);

    const uint64_t overlap = std::min(receiver_candidate_count, ground_truth);
    oc::PRNG prng(oc::block(seed, seed ^ kHashSeed0));
    std::unordered_set<BlockWords, BlockWordsHash> used;
    used.reserve(static_cast<size_t>(receiver_candidate_count + overlap) * 2);

    auto next_unique_block = [&]() {
        for (;;) {
            const oc::block candidate = prng.get<oc::block>();
            const BlockWords key = unpackBlock(candidate);
            if (used.insert(key).second) {
                return candidate;
            }
        }
    };

    dataset.sender_ids.reserve(overlap);
    for (uint64_t i = 0; i < overlap; ++i) {
        const oc::block id = next_unique_block();
        dataset.sender_ids.push_back(id);
        dataset.receiver_ids.push_back(id);
        dataset.receiver_truth_mask.push_back(1);
    }

    while (dataset.receiver_ids.size() < receiver_candidate_count) {
        dataset.receiver_ids.push_back(next_unique_block());
        dataset.receiver_truth_mask.push_back(0);
    }

    std::mt19937_64 shuffle_rng(seed ^ kHashSeed1);
    for (size_t i = dataset.receiver_ids.size(); i > 1; --i) {
        const size_t j = static_cast<size_t>(shuffle_rng() % i);
        std::swap(dataset.receiver_ids[i - 1], dataset.receiver_ids[j]);
        std::swap(dataset.receiver_truth_mask[i - 1], dataset.receiver_truth_mask[j]);
    }

    return dataset;
}

std::vector<uint8_t> buildSerializedPrefilter(
    PrefilterKind kind,
    const std::vector<oc::block> &sender_ids,
    double target_fpr)
{
    switch (kind) {
    case PrefilterKind::Bloom:
        return BloomFilter(sender_ids, target_fpr).serialize();
    case PrefilterKind::VirtualBloom:
        return VirtualBloomFilter(sender_ids, target_fpr).serialize();
    case PrefilterKind::Cuckoo:
        return CuckooFilter(sender_ids, target_fpr).serialize();
    case PrefilterKind::Xor:
        return XorFilter(sender_ids, target_fpr).serialize();
    }

    throw std::runtime_error("unsupported prefilter kind");
}

std::vector<uint32_t> querySerializedPrefilter(
    PrefilterKind kind,
    const std::vector<uint8_t> &serialized_filter,
    const std::vector<oc::block> &receiver_ids)
{
    std::vector<uint32_t> kept_indices;
    kept_indices.reserve(receiver_ids.size());

    auto keep_if_match = [&](auto &&filter) {
        for (uint32_t i = 0; i < receiver_ids.size(); ++i) {
            if (filter.contains(receiver_ids[i])) {
                kept_indices.push_back(i);
            }
        }
    };

    switch (kind) {
    case PrefilterKind::Bloom:
        keep_if_match(BloomFilter::deserialize(serialized_filter));
        return kept_indices;
    case PrefilterKind::VirtualBloom:
        keep_if_match(VirtualBloomFilter::deserialize(serialized_filter));
        return kept_indices;
    case PrefilterKind::Cuckoo:
        keep_if_match(CuckooFilter::deserialize(serialized_filter));
        return kept_indices;
    case PrefilterKind::Xor:
        keep_if_match(XorFilter::deserialize(serialized_filter));
        return kept_indices;
    }

    throw std::runtime_error("unsupported prefilter kind");
}

std::vector<PrefilterBenchResult> runPrefilterBenchmarks(const PrefilterBenchConfig &config)
{
    if (config.receiver_candidate_count == 0) {
        throw std::runtime_error("receiver candidate count must be positive");
    }
    if (config.target_fpr <= 0.0 || config.target_fpr >= 1.0) {
        throw std::runtime_error("target fpr must be in (0, 1)");
    }

    const auto kinds = parsePrefilterSelection(config.filter);
    std::vector<ResultAccumulator> accumulators(kinds.size());

    const uint64_t try_count = std::max<uint64_t>(1, config.try_count);
    for (uint64_t trial = 0; trial < try_count; ++trial) {
        const PrefilterDataset dataset = generatePrefilterDataset(
            config.receiver_candidate_count,
            config.ground_truth,
            splitMix64(config.seed + trial * 0x9E3779B97F4A7C15ULL));

        for (size_t i = 0; i < kinds.size(); ++i) {
            accumulators[i].add(runBenchCase(kinds[i], dataset, config.target_fpr));
        }
    }

    std::vector<PrefilterBenchResult> results;
    results.reserve(kinds.size());
    for (const auto &accumulator : accumulators) {
        results.push_back(accumulator.average());
    }
    return results;
}

void printPrefilterBenchMarkdown(
    const std::vector<PrefilterBenchResult> &results,
    const PrefilterBenchConfig &config)
{
    const std::array<PrefilterKind, 4> display_kinds = {
        PrefilterKind::Bloom,
        PrefilterKind::VirtualBloom,
        PrefilterKind::Cuckoo,
        PrefilterKind::Xor
    };

    auto findResult = [&](PrefilterKind kind) -> const PrefilterBenchResult * {
        const std::string name = prefilterKindName(kind);
        for (const auto &result : results) {
            if (result.name == name) {
                return &result;
            }
        }
        return nullptr;
    };

    std::cout << "Ground Truth = " << config.ground_truth
              << ", Receiver Candidates = " << config.receiver_candidate_count
              << ", Try Count = " << std::max<uint64_t>(1, config.try_count)
              << ", Target FPR = " << config.target_fpr << std::endl;
    std::cout << std::endl;

    auto cell = [&](PrefilterKind kind, const auto &formatter) {
        const PrefilterBenchResult *result = findResult(kind);
        if (result == nullptr) {
            return std::string("N/A");
        }
        return formatter(*result);
    };

    auto printHeader = [&]() {
        std::cout << "| Metric |";
        for (PrefilterKind kind : display_kinds) {
            std::cout << ' ' << prefilterKindName(kind) << " |";
        }
        std::cout << std::endl;
        std::cout << "|--------|";
        for (size_t i = 0; i < display_kinds.size(); ++i) {
            std::cout << "----------------------|";
        }
        std::cout << std::endl;
    };

    auto printRow = [&](std::string_view label, const auto &formatter) {
        std::cout << "| " << label << " |";
        for (PrefilterKind kind : display_kinds) {
            std::cout << ' ' << cell(kind, formatter) << " |";
        }
        std::cout << std::endl;
    };

    printHeader();
    printRow("Build Time", [](const PrefilterBenchResult &r) { return formatTime(r.build_time_us); });
    printRow("Serialized Size", [](const PrefilterBenchResult &r) { return formatBytes(r.serialized_size_bytes); });
    printRow("Query Time", [](const PrefilterBenchResult &r) { return formatTime(r.query_time_us); });
    printRow("id_generated_total", [](const PrefilterBenchResult &r) { return formatCount(r.id_generated_total); });
    printRow("id_filtered_total", [](const PrefilterBenchResult &r) { return formatCount(r.id_filtered_total); });
    printRow("id_used_total", [](const PrefilterBenchResult &r) { return formatCount(r.id_used_total); });
    printRow("Redundancy Rate", [](const PrefilterBenchResult &r) { return formatRate(r.redundancy_rate); });
    std::cout << std::endl;
    printHeader();
    printRow("False Positives", [](const PrefilterBenchResult &r) { return formatCount(r.false_positives); });
    printRow("Ground Truth", [](const PrefilterBenchResult &r) { return formatCount(r.ground_truth); });
}

} // namespace fpsi::prefilter
