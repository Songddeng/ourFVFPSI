#pragma once
#include "secure-join/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Aligned.h"

namespace secJoin
{

    extern const std::array<u32, 256> mod3TableV;
    extern const std::array<u32, 256> mod3TableLsb;
    extern const std::array<u32, 256> mod3TableMsb;
    //extern std::array<std::array<u8, 5>, 256> const mod3TableFull;

    // z =  x + y mod 3
    OC_FORCEINLINE void mod3Add(
        block& z1, block& z0,
        const block& x1, const block& x0,
        const block& y1, const block& y0)
    {
        auto x1x0 = x1 ^ x0;
        auto zz1 = (y0 ^ x0).andnot_si128(x1x0 ^ y1);
        auto zz0 = (x1 ^ y1).andnot_si128(x1x0 ^ y0);

        z0 = zz0;
        z1 = zz1;
    }


    // z =  x - y mod 3
    OC_FORCEINLINE void mod3Sub(
        block& z1, block& z0,
        const block& x1, const block& x0,
        const block& y1, const block& y0)
    {
        // swap y0,y1;
        mod3Add(z1, z0, x1, x0, y0, y1);
    }


    // z =  x + y mod 3
    inline void mod3Add(
        span<block> z1, span<block> z0,
        span<const block> x1, span<const block> x0,
        span<const block> y1, span<const block> y0)
    {
        assert(z1.size() == z0.size());
        assert(z1.size() == x0.size());
        assert(z1.size() == y0.size());
        assert(x1.size() == x0.size());
        assert(y1.size() == y0.size());

        //auto x1x0 = x1 ^ x0;
        //auto z1 = (1 ^ y0 ^ x0) * (x1x0 ^ y1);
        //auto z0 = (1 ^ x1 ^ y1) * (x1x0 ^ y0);
        //auto e = (x + y) % 3;
        for (u64 i = 0; i < z0.size(); ++i)
        {
            auto x1i = x1.data()[i];
            auto x0i = x0.data()[i];
            auto y1i = y1.data()[i];
            auto y0i = y0.data()[i];
            auto x1x0 = x1i ^ x0i;
            z1.data()[i] = (y0i ^ x0i).andnot_si128(x1x0 ^ y1i);
            z0.data()[i] = (x1i ^ y1i).andnot_si128(x1x0 ^ y0i);
        }
    }

    inline void mod3Add(
        block& z1, block& z0,
        const block& x1, const block& x0,
        const block& y0)
    {
        auto ab = x1 ^ x0;
        auto abc = ab & y0;

        auto zz1 = x1 ^ abc;

        auto nac = x1.andnot_si128(y0);
        auto zz0 = x0 ^ nac;

        z1 = zz1;
        z0 = zz0;
    }


    // z = x + y mod 3
    // we treat binary x1 as the MSB and binary x0 as lsb.
    // That is, for bits, x1 x0 y0, we sets 
    //   t = x1 * 2 + x0 + y0
    //   x1 = t / 2
    //   x0 = t % 2
    inline void mod3Add(
        span<block> z1, span<block> z0,
        span<const block> x1, span<const block> x0,
        span<const block> y0)
    {
        //auto z1 = x1 ^ (x1 ^ x0) * y0;
        //auto z0 = x0 ^ (1 ^ x1) * y0;
        assert(z1.size() == z0.size());
        assert(z1.size() == x0.size());
        assert(z1.size() == y0.size());
        assert(x1.size() == x0.size());


        for (u64 i = 0; i < x1.size(); ++i)
        {
            mod3Add(z1.data()[i], z0.data()[i], x1.data()[i], x0.data()[i], y0.data()[i]);
        }
    }

    // z = x-y mod 3
    // we treat binary x1 as the MSB and binary x0 as lsb.
    // That is, for bits, x1 x0 y0, we sets 
    //   t = x1 * 2 + x0 + y0
    //   x1 = t / 2
    //   x0 = t % 2
    inline void mod3Sub(
        span<block> z1, span<block> z0,
        span<const block> x1, span<const block> x0,
        span<const block> y0)
    {
        assert(z1.size() == z0.size());
        assert(z1.size() == x0.size());
        assert(z1.size() == y0.size());
        assert(x1.size() == x0.size());

        for (u64 i = 0; i < x1.size(); ++i)
        {
            auto x1i = x1.data()[i];
            auto x0i = x0.data()[i];
            auto y1i = y0.data()[i];
            auto x1x0 = x1i ^ x0i;
            z1.data()[i] = (x0i).andnot_si128(x1x0 ^ y1i);
            z0.data()[i] = (x1i ^ y1i).andnot_si128(x1x0);
        }
    }



    // z = x-y mod 3
    // we treat binary x1 as the MSB and binary x0 as lsb.
    inline void mod3Sub(
        span<block> z1, span<block> z0,
        span<const block> x1, span<const block> x0,
        span<const block> y1, span<const block> y0)
    {
        // swaping the bits is negation
        mod3Add(z1, z0, x1, x0, y0, y1);
    }


    // z += y mod 3
    inline void mod3Add(
        span<block> z1, span<block> z0,
        span<const block> y1, span<const block> y0)
    {
        assert(z1.size() == z0.size());
        assert(z1.size() == y0.size());
        assert(y1.size() == y0.size());

        block* __restrict z1d = z1.data();
        block* __restrict z0d = z0.data();
        const block* __restrict y1d = y1.data();
        const block* __restrict y0d = y0.data();

        //auto x1x0 = x1 ^ x0;
        //auto z1 = (1 ^ y0 ^ x0) * (x1x0 ^ y1);
        //auto z0 = (1 ^ x1 ^ y1) * (x1x0 ^ y0);
        //auto e = (x + y) % 3;
        for (u64 i = 0; i < z0.size(); ++i)
        {
            auto x1i = z1d[i];
            auto x0i = z0d[i];
            auto y1i = y1d[i];
            auto y0i = y0d[i];
            auto x1x0 = x1i ^ x0i;
            z1d[i] = (y0i ^ x0i).andnot_si128(x1x0 ^ y1i);
            z0d[i] = (x1i ^ y1i).andnot_si128(x1x0 ^ y0i);
        }
    }

    // z += y mod 3
    OC_FORCEINLINE void mod3Add(block& z1, block& z0, const block& y0)
    {
        auto x1 = z1;
        auto x0 = z0;
        auto x1x0 = x1 ^ x0;
        z1 = (y0 ^ x0).andnot_si128(x1x0);
        z0 = (x1).andnot_si128(x1x0 ^ y0);
    }

    // z += y mod 3
    inline void mod3Add(
        span<block> z1, span<block> z0,
        span<const block> y0)
    {
        assert(z1.size() == z0.size());
        assert(z1.size() == y0.size());

        block* __restrict z1d = z1.data();
        block* __restrict z0d = z0.data();
        const block* __restrict y0d = y0.data();

        for (u64 i = 0; i < z0.size(); ++i)
        {
            mod3Add(z1d[i], z0d[i], y0d[i]);
        }
    }

    // sample many mod 3 values in bit decomposed format.
    void sampleMod3Lookup(PRNG& prng, span<block> msb, span<block> lsb);

    // sample 8 mod three values, where the i'th is sampled using seed[i]. 
    void sample8Mod3(block* seed, u8& msb, u8& lsb);

    // sample many mod three values, where the i'th is sampled using seed[i]. 
    // seed.size() must be a multiple of 128.
    void sampleMod3(span<block> seed, span<block> msb, span<block> lsb);
}