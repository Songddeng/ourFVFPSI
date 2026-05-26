#pragma once

#include "secure-join/Defines.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Perm/Permutation.h"
#include "secure-join/Perm/PermCorrelation.h"


namespace secJoin
{
    // The sender half of the protocol to generate a permutation correlation
    // using the AltMod Prf as a subprotocol. The result of this protocol
    // is the sender holding a PermCorSender, i.e. a permutation pi and a sharing of
    // pi(A). The receiver will hold a PermCorSender, i.e. a vector A and sharing of 
    // pi(A).
    class AltModPermGenSender
    {
    public:
        bool mDebug = false;

        // the underlaying PRF protocol.
        AltModWPrfReceiver mPrfRecver;

        // the size of the permutation to be generated.
        u64 mN = 0;

        // the number of bytes per element to be generated.
        u64 mBytesPerRow = 0;

        AltModPermGenSender() = default;
        AltModPermGenSender(const AltModPermGenSender&) = delete;
        AltModPermGenSender(AltModPermGenSender&&) noexcept = default;
        AltModPermGenSender& operator=(const AltModPermGenSender&) = delete;
        AltModPermGenSender& operator=(AltModPermGenSender&&) noexcept = default;

        // initialize this sender to have a permutation of size n, where 
        // bytesPerRow bytes can be permuted per position. keyGen can be 
        // set if the caller wants to explicitly ask to perform AltMod keygen or not.
        void init(
            u64 n, 
            u64 bytesPerRow,
            CorGenerator& cor,
            span<std::array<block, 2>> atlModKeys = {}
            )
        {
            mN = n;
            mBytesPerRow = bytesPerRow;
            u64 blocks = n * divCeil(bytesPerRow, sizeof(block));
            mPrfRecver.init(blocks, cor, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly,  {}, atlModKeys);
        }

        // this will request CorGen to start our preprocessing
        void preprocess()
        {
            mPrfRecver.preprocess();
        }

        // Generate the correlated randomness for the permutation pi. pi will either
        // be mPi if it is already known or it will be mPrePerm.
        macoro::task<> generate(
            Perm perm,
            PRNG& prng,
            coproto::Socket& chl,
            PermCorSender& dst);

        void clear() {
            mPrfRecver.clear();
            mN = 0;
            mBytesPerRow = 0;
        }
    };


    // The receiver half of the protocol to generate a permutation correlation
    // using the AltMod Prf as a subprotocol. The result of this protocol
    // is the sender holding a PermCorSender, i.e. a permutation pi and a sharing of
    // pi(A). The receiver will hold a PermCorSender, i.e. a vector A and sharing of 
    // pi(A).
    class AltModPermGenReceiver
    {
    public:
        bool mDebug = false;

        // The AltMod prf sender protocol.
        AltModWPrfSender mPrfSender;

        // the size of the permutation.
        u64 mN = 0;

        // the number of bytes per element to be generated.
        u64 mBytesPerRow = 0;

        AltModPermGenReceiver() = default;
        AltModPermGenReceiver(const AltModPermGenReceiver&) = delete;
        AltModPermGenReceiver(AltModPermGenReceiver&&) noexcept = default;
        AltModPermGenReceiver& operator=(const AltModPermGenReceiver&) = delete;
        AltModPermGenReceiver& operator=(AltModPermGenReceiver&&) noexcept = default;

        // initialize this receiver to have a permutation of size n, where 
        // bytesPerRow bytes can be permuted per position. keyGen can be 
        // set if the caller wants to explicitly ask to perform AltMod keygen or not.
        void init(
            u64 n, 
            u64 bytesPerRow,
            CorGenerator& cor,
            macoro::optional<AltModPrf::KeyType> altModKey = {},
            span<block> altModKeyOts = {})
        {
            mN = n;
            mBytesPerRow = bytesPerRow;

            u64 blocks = n * divCeil(bytesPerRow, sizeof(block));
            mPrfSender.init(blocks, cor, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, altModKey, altModKeyOts);
        }

        // generete preprocessing for a rnadom permutation. This can be derandomized to a chosen perm later.
        void preprocess()
        {
            mPrfSender.preprocess();
        }

        // Generate the correlated randomness.
        macoro::task<> generate(
            PRNG& prng,
            coproto::Socket& chl,
            PermCorReceiver& dst);
    };
}