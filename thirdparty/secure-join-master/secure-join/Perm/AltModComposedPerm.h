#pragma once
#include "secure-join/Perm/ComposedPerm.h"
#include "secure-join/Perm/AltModPerm.h"
#include "macoro/optional.h"

namespace secJoin
{


    // A protocool to generated a shared permutation where P0 holds pi_0 and P1 holds pi_1
    // such that the combined permutation is pi = pi_1 o pi_0.
    // init(...) should be called and then generate(...) to get the actual 
    // permutation.
    class AltModComposedPerm
    {
    public:
        // {0,1} to determine which party permutes first
        u64 mPartyIdx = -1;

        // The permutation protocol for mPi
        AltModPermGenSender mPermSender;

        // The permutation protocol for the other share.
        AltModPermGenReceiver mPermReceiver;

        AltModComposedPerm() = default;
        AltModComposedPerm(const AltModComposedPerm&) = delete;
        AltModComposedPerm(AltModComposedPerm&&) noexcept = default;
        AltModComposedPerm& operator=(const AltModComposedPerm&) = delete;
        AltModComposedPerm& operator=(AltModComposedPerm&&) noexcept = default;

        // initialize the permutation generation protocol.
        // `partyIdx` should be 0,1.
        // `size` is the number of elements permutated.
        // `bytesPerRow` is the size of each element in bytes
        // `cor` is the source of correlated randomness
        // `altModKey`, `altModKeySendOts`, `altModKeyRecvOts` are optional
        // parameters that can be used to initialize the underlying AltMod PRF protocol.
        void init(
            u8 partyIdx,
            u64 size,
            u64 bytesPerRow,
            CorGenerator& cor,
            macoro::optional<AltModPrf::KeyType> altModKey = {},
            span<std::array<block, 2>> altModKeySendOts = {},
            span<block> altModKeyRecvOts = {})
        {
            mPartyIdx = partyIdx;
            if (partyIdx)
            {
                mPermReceiver.init(size, bytesPerRow, cor, altModKey, altModKeyRecvOts);
                mPermSender.init(size, bytesPerRow, cor, altModKeySendOts);
            }
            else
            {
                mPermSender.init(size, bytesPerRow, cor, altModKeySendOts);
                mPermReceiver.init(size, bytesPerRow, cor, altModKey, altModKeyRecvOts);
            }
        }

        // Generate the required correlated randomness.
        void preprocess();

        // generate the permutation correlation
        macoro::task<> generate(
            coproto::Socket& chl,
            PRNG& prng,
            Perm perm,
            ComposedPerm& dst);

        // generate the permutation correlation
        macoro::task<> generate(
            coproto::Socket& chl,
            PRNG& prng,
            u64 size,
            ComposedPerm& dst)
        {
            return generate(chl, prng, Perm(size, prng), dst);
        }

    };
}