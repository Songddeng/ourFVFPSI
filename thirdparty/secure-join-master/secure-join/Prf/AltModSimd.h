#pragma once
#include <bitset>
#include <array>
#include "secure-join/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"

namespace secJoin
{

    // returns the i'th bit of x.
    template<typename T>
    int bit(T* x, u64 i)
    {
        return  *oc::BitIterator((u8*)x, i);
    }
    // returns the i'th bit of x.
    template<typename T>
    int bit(T& x, u64 i)
    {
        return  *oc::BitIterator((u8*)&x, i);
    }

    // returns the i'th 2-bit value of x.
    template<typename T>
    int bit2(T& x, u64 i)
    {
        return  *oc::BitIterator((u8*)&x, i * 2) + 2 * *oc::BitIterator((u8*)&x, i * 2 + 1);;
    }

    // v ^= prng.get()
    inline void xorVector(span<oc::block> v, PRNG& prng)
    {
        oc::block m[8];
        auto vIter = v.data();
        auto n = v.size();
        assert(u64(v.data()) % 16 == 0);

        auto j = 0ull;
        auto main = n / 8 * 8;
        for (; j < main; j += 8)
        {
            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, 8, m);
            prng.mBlockIdx += 8;

            vIter[0] = vIter[0] ^ m[0];
            vIter[1] = vIter[1] ^ m[1];
            vIter[2] = vIter[2] ^ m[2];
            vIter[3] = vIter[3] ^ m[3];
            vIter[4] = vIter[4] ^ m[4];
            vIter[5] = vIter[5] ^ m[5];
            vIter[6] = vIter[6] ^ m[6];
            vIter[7] = vIter[7] ^ m[7];
            vIter += 8;
        }
        for (; j < n; ++j)
        {
            auto m = prng.mAes.ecbEncBlock(oc::toBlock(prng.mBlockIdx++));
            //oc::block m = prng.get();
            *vIter = *vIter ^ m;
            ++vIter;
        }
        assert(vIter == v.data() + v.size());
    }



    // v = u ^ PRNG()
    inline void xorVectorOne(span<oc::block> v, span<const oc::block> u, PRNG& prng)
    {
        oc::block m[8];
        auto vIter = v.data();
        auto uIter = u.data();
        auto n = v.size();
        assert(u64(v.data()) % 16 == 0);

        auto j = 0ull;
        auto main = n / 8 * 8;
        for (; j < main; j += 8)
        {
            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, 8, m);
            prng.mBlockIdx += 8;

            vIter[0] = uIter[0] ^ m[0];
            vIter[1] = uIter[1] ^ m[1];
            vIter[2] = uIter[2] ^ m[2];
            vIter[3] = uIter[3] ^ m[3];
            vIter[4] = uIter[4] ^ m[4];
            vIter[5] = uIter[5] ^ m[5];
            vIter[6] = uIter[6] ^ m[6];
            vIter[7] = uIter[7] ^ m[7];
            vIter += 8;
            uIter += 8;
        }
        for (; j < n; ++j)
        {
            auto m = prng.mAes.ecbEncBlock(oc::toBlock(prng.mBlockIdx++));
            //oc::block m = prng.get();

            *vIter = *uIter ^ m;
            ++vIter;
            ++uIter;
        }
        assert(vIter == v.data() + v.size());
    }

    // out = (hi0, hi1) ^ prng()
    inline void xorVectorOne(
        span<block> out1,
        span<block> out0,
        span<block> m1,
        span<block> m0,
        PRNG& prng)
    {
        xorVectorOne(out1, m1, prng);
        xorVectorOne(out0, m0, prng);
    }

    // out = (hi0, hi1) ^ prng()
    inline void xorVectorOne(
        span<block> out,
        span<block> m1,
        span<block> m0,
        PRNG& prng)
    {
        xorVectorOne(out.subspan(m0.size()), m1, prng);
        xorVectorOne(out.subspan(0, m0.size()), m0, prng);
    }

}