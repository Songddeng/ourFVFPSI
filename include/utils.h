#pragma once

#include <algorithm>
#include <bitset>
#include <cmath>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/AES.h>
#include <emmintrin.h>
#include <libOTe/TwoChooseOne/ConfigureCode.h>
#include <tuple>
#include <vector>

using namespace osuCrypto;

std::tuple<std::vector<std::vector<u64>>, std::vector<std::vector<u64>>> genInputs(u64 n, u64 d);

inline u64 low(oc::block &blk)
{
    u64 low64 = _mm_extract_epi64(blk, 0);

    return low64;
}

inline u64 high(oc::block &blk)
{
    u64 high64 = _mm_extract_epi64(blk, 1);

    return high64;
}

// Decompose the interval [start, end] using an improved method in appendix
inline std::vector<block> getIntervalPrefix(u64 start, u64 end, int shift = 0)
{
    if (start > end) {
        throw std::runtime_error("decompose improve: end should >= start");
    }

    if (start == end) {
        return { block(0, start) };
    }

    u64 interval_len = end - start + 1; // interval length
    u64 bit_width = static_cast<u64>(std::log2(interval_len)) + 1;
    u64 aligned_start = start;

    // step 1
    // find aligned_start >= start, s.t. 2^(bit_width-1) | aligned_start
    while (aligned_start <= end && (aligned_start & ((1 << (bit_width - 1)) - 1))) {
        aligned_start++;
    }

    if (aligned_start > end) {
        throw std::runtime_error("decompose improve: can't find aligned_start");
    }

    // step 2
    // right_len = end - aligned_start + 1; left_len = aligned_start - start
    u64 right_len = end - aligned_start + 1; // right side length
    u64 left_len = aligned_start - start;    // left side length

    // convert to binary representation, bitset access is from low bit to high bit
    std::bitset<64> right_bits(right_len); // right_len + left_len = 2\delta + 1
    std::bitset<64> left_bits(left_len);

    std::vector<block> results;       // result set
    u64 right_pos = aligned_start;    // move right
    u64 left_pos = aligned_start - 1; // move left

    std::vector<block> temp_results;

    // traverse from high bit to low bit
    for (u64 i = bit_width; i >= 1; i--) {
        if (right_bits[i - 1]) {
            // if right_len's i-th bit is 1
            if (i - 1 > (bit_width - 1 - shift)) {
                temp_results.push_back(block(i - 1, right_pos >> (i - 1)));
            } else {
                results.push_back(block(i - 1, right_pos >> (i - 1)));
            }
            right_pos += (1 << (i - 1));
        }
        if (left_bits[i - 1]) {
            // if left_len's i-th bit is 1
            if (i - 1 > (bit_width - 1 - shift)) {
                temp_results.push_back(block(i - 1, left_pos >> (i - 1)));
            } else {
                results.push_back(block(i - 1, left_pos >> (i - 1)));
            }
            left_pos -= (1 << (i - 1));
        }
    }

    if (shift != 0) {
        for (int i = 0; i < temp_results.size(); i++) {
            int len = high(temp_results[i]);
            u64 base = low(temp_results[i]);
            for (int j = 0; j < (1 << (len - (bit_width - 1 - shift))); j++) {
                results.push_back(block(bit_width - 1 - shift, (base << (len - (bit_width - 1 - shift))) + j));
            }
        }
    }

    return results;
}

inline u64 firstLessThan(u64 x, const std::vector<u64> &U)
{
    auto it = std::lower_bound(U.begin(), U.end(), x); // find the first element not less than x

    if (it == U.begin()) {
        // No element is less than x, return 0 or other appropriate value
        return 0;
    }

    --it; // Move to the largest element less than x
    return *it;
}

inline std::vector<block> getIntervalPrefixSet(u64 start, u64 end, std::vector<u64> U)
{
    std::vector<block> finalPrefixes;
    auto prefixes = getIntervalPrefix(start, end);
    for (auto &p : prefixes) {
        u64 len = high(p);
        u64 base = low(p);
        if (std::find(U.begin(), U.end(), len) != U.end()) {
            finalPrefixes.push_back(p);
        } else {
            u64 newLen = firstLessThan(len, U);

            for (int j = 0; j < (1 << (len - newLen)); j++) {
                finalPrefixes.push_back(block(newLen, (base << (len - newLen)) + j));
            }
        }
    }

    return finalPrefixes;
}

inline std::vector<block> getPrefix(u64 x, int maxLen)
{
    std::vector<block> res;

    for (int len = 0; len < maxLen; len++) {
        res.push_back(block(len, x >> (len)));
    }

    return res;
}

inline std::vector<block> getPrefixSet(u64 x, std::vector<u64> U)
{
    std::vector<block> res;

    for (auto &len : U) {
        res.push_back(block(len, x >> (len)));
    }

    return res;
}

inline u64 upBound(block prefix)
{
    u64 len = high(prefix);
    u64 base = low(prefix);
    u64 upper = (1 << len) - 1 + (base << len);

    return upper;
}

inline u64 lowBound(block prefix)
{
    u64 len = high(prefix);
    u64 base = low(prefix);
    u64 lower = base << len;

    return lower;
}

void inline Hash(std::vector<block> &input)
{
    auto n8 = input.size() / 8 * 8;

    // notOneBlock
    // block mask = OneBlock ^ AllOneBlock;

    auto r = input.data();

    for (u64 i = 0; i < n8; i += 8) {
        // r[0] = r[0] & mask;
        // r[1] = r[1] & mask;
        // r[2] = r[2] & mask;
        // r[3] = r[3] & mask;
        // r[4] = r[4] & mask;
        // r[5] = r[5] & mask;
        // r[6] = r[6] & mask;
        // r[7] = r[7] & mask;

        oc::mAesFixedKey.hashBlocks<8>(r, r);
        r += 8;
    }
    for (u64 i = n8; i < input.size(); i++) {
        // input[i] = input[i] & mask;
        input[i] = oc::mAesFixedKey.hashBlock(input[i]);
    }
}

inline uint64_t combination(uint64_t n, uint64_t k)
{
    if (k > n)
        return 0;
    if (k == 0 || k == n)
        return 1;

    // C(n, k) = C(n, n-k)
    if (k > n - k)
        k = n - k;

    uint64_t result = 1;
    for (uint64_t i = 1; i <= k; ++i) {
        result = result * (n - i + 1) / i;
    }

    return result;
}

const osuCrypto::MultType type = osuCrypto::MultType::Tungsten;