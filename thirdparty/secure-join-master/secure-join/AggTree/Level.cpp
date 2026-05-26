
#include "Level.h"

namespace secJoin
{
    void PLevel::reveal(AggTreeSplitLevel& tvs0, AggTreeSplitLevel& tvs1)
    {
        PLevel l0, l1;
        l0.reveal(tvs0[0], tvs1[0]);
        l1.reveal(tvs0[1], tvs1[1]);

        perfectUnshuffle(l0, l1);
    }


    auto revealOne(
        std::vector<oc::BitVector>& dst,
        TBinMatrix& src0,
        TBinMatrix& src1,
        bool print = false)
    {
        auto v0 = src0.transpose();
        auto v1 = src1.transpose();
        dst.resize(src0.numEntries());
        for (u64 i = 0; i < dst.size(); ++i)
        {
            dst[i].resize(src0.bitsPerEntry());
            for (u64 j = 0; j < dst[i].sizeBytes(); ++j)
            {
                dst[i].getSpan<u8>()[j] = v0(i, j) ^ v1(i, j);
            }
        }
    }

    auto revealOne(
        oc::BitVector& dst,
        TBinMatrix& src0,
        TBinMatrix& src1)
    {
        assert(src0.bitsPerEntry() < 2);
        assert(src1.bitsPerEntry() < 2);
        dst.resize(src0.numEntries());

        for (u64 i = 0; i < dst.sizeBytes(); ++i)
        {
            dst.getSpan<u8>()[i] = src0(i) ^ src1(i);
        }
    };

    void PLevel::reveal(AggTreeLevel& tvs0, AggTreeLevel& tvs1)
    {
        revealOne(mPreBit, tvs0.mPreBit, tvs1.mPreBit);
        revealOne(mPreVal, tvs0.mPreVal, tvs1.mPreVal, true);
        revealOne(mSufBit, tvs0.mSufBit, tvs1.mSufBit);
        revealOne(mSufVal, tvs0.mSufVal, tvs1.mSufVal);
    }


    void PLevel::perfectUnshuffle(PLevel& l0, PLevel& l1)
    {

        auto shuffle = [](auto& l0, auto& l1, auto& out)
        {
            auto size = l0.size() + l1.size();
            out.resize(size);

            for (u64 i = 0; i < size; i += 2)
            {
                out[i + 0] = l0[i / 2];

                if (i + 1 < size)
                    out[i + 1] = l1[i / 2];
            }

        };

        shuffle(l0.mPreVal, l1.mPreVal, mPreVal);
        shuffle(l0.mPreBit, l1.mPreBit, mPreBit);
        shuffle(l0.mSufVal, l1.mSufVal, mSufVal);
        shuffle(l0.mSufBit, l1.mSufBit, mSufBit);
    }
}