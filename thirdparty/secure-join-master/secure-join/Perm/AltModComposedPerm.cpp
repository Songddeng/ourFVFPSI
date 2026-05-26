#include "AltModComposedPerm.h"

namespace secJoin
{

    void AltModComposedPerm::preprocess()
    {
        mPermSender.preprocess();
        mPermReceiver.preprocess();
    }

    macoro::task<> AltModComposedPerm::generate(
        coproto::Socket& chl,
        PRNG& prng_,
        Perm perm,
        ComposedPerm& dst)
    {
        if (mPermSender.mPrfRecver.mInputSize == 0)
            throw RTE_LOC;
        auto prng = PRNG(prng_.get<oc::block>());
        auto chl2 = coproto::Socket{ };
        auto prng2 = prng_.fork();
        auto t0 = macoro::task<>{};
        auto t1 = macoro::task<>{};

// #ifndef NDEBUG
//         perm.validate();
// #endif

        chl2 = chl.fork();
        dst.mPartyIdx = mPartyIdx;

        if (mPartyIdx)
        {
            t0 = mPermSender.generate(std::move(perm), prng, chl, dst.mPermSender);
            t1 = mPermReceiver.generate(prng2, chl2, dst.mPermReceiver);
        }
        else
        {
            t0 = mPermReceiver.generate(prng2, chl, dst.mPermReceiver);
            t1 = mPermSender.generate(std::move(perm), prng, chl2, dst.mPermSender);
        }

        co_await macoro::when_all_ready(std::move(t0), std::move(t1));

    }
}
