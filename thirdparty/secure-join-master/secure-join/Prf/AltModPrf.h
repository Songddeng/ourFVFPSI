
#pragma once
#include "secure-join/config.h"
#include "secure-join/Defines.h"
#include "secure-join/CorGenerator/CorGenerator.h"

#include "macoro/optional.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Aligned.h"

#include "F2LinearCode.h"
#include "F3LinearCode.h"

namespace secJoin
{
    // For the shared protocol, is the key secret shared?
    enum class AltModPrfKeyMode
    {
        SenderOnly,
        Shared
    };

    // For the shared protocol, is the input secret shared?
    enum class AltModPrfInputMode
    {
        ReceiverOnly,
        Shared
    };

    // is the input x expanded using AES.hash(x) or G * x?
    enum class AltModPrfExpansionMode
    {
        Random,
        Linear
    };

    // The strong Alteranting moduli PRF of Alamati et al.
    //
    // F(k, x):
    //   e = G * x        mod 2
    //   v = A * (e . k)  mod 3
    //   w = B * v        mod 2
    //   return w
    //
    // It can also be instanted as the "weak PRF" where
    // e is defined as AES.hash(x) and otherwise the same. 
    class AltModPrf
    {
    public:
        // the B matrix where the first part is implicit in systematic form.
        // i.e. B * v = mB * v + v
        static const std::array<oc::block, 128> mB;

        // the same as  mB but where each bit is represented as a byte. This
        // is helpful in some places.
        static const std::array<std::array<u8, 128>, 128> mBExpanded;

        // a preprocessed linear code the makes computing B * v fast.
        static const F2LinearCode mBCode;

        // The A matrix. Instead of using a randon linear code we use a sparse
        // iterative turbo code. The idea to iteratively perform prefix sums over 
        // the input and then permuting it. 
        static const F3AccPermCode mACode;

        // The G matrix where the first part is implicirely in systematic form.
        // i.e. G * x = mGCode * x + x
        static const std::array<F2LinearCode, 3> mGCode;


        // A flag that is used to select if e = G * x (linear) or e = AES(x) (random).
        AltModPrfExpansionMode mInputExpansionMode = AltModPrfExpansionMode::Linear;

        // the bit count of the key, i.e k
        static constexpr auto KeySize = 128 * 4;

        // the bit count of the middle layer, i.e. v
        static constexpr auto MidSize = 256;

        // the bit count of output layer, i.e. w
        static constexpr auto OutSize = 128;

        struct KeyType : std::array<oc::block, KeySize / 128>
        {
            KeyType operator^(const KeyType& o) const
            {
                KeyType r;
                for (u64 i = 0;i < size(); ++i)
                    r[i] = (*this)[i] ^ o[i];
                return r;
            }
        };

        KeyType mExpandedKey;

        AltModPrf() = default;
        AltModPrf(const AltModPrf&) = default;
        AltModPrf& operator=(const AltModPrf&) = default;
        AltModPrf(KeyType k)
        {
            setKey(k);
        }

        // set the key
        void setKey(KeyType k);

        KeyType getKey() const { return mExpandedKey; }

        // compute y = F(k,x)
        void eval(span<oc::block> x, span<oc::block> y);

        // compute y = F(k,x)
        oc::block eval(oc::block x);

        // expands a single 128 bit input either using AES 
        // or a random linear code depending on the mode.
        static void expandInput(block x, KeyType& expanded, AltModPrfExpansionMode mode = AltModPrfExpansionMode::Linear)
        {
            if(mode == AltModPrfExpansionMode::Linear)
                expandInputLinear(x, expanded);
            else
                expandInputAes(x, expanded);
        }

        // expands a many 128 bit inputs either using AES 
        // or a random linear code depending on the mode.
        static void expandInput(span<const block> x, oc::MatrixView<block> expanded, AltModPrfExpansionMode mode = AltModPrfExpansionMode::Linear)
        {
            if(mode == AltModPrfExpansionMode::Linear)
                expandInputLinear(x, expanded);
            else
                expandInputAes(x, expanded);
        }

        // take as input a single 128 bit input and expand it into 512 bit 
        // "random" value. This 512 bit value will be used as the "weak" PRF input.
        // Concretely, expanded = (x, AES.hash(x + 1), AES.hash(x + 2), AES.hash(x + 3)).
        // Assuming x is random, then so is expanded.
        static void expandInputAes(block x, KeyType& expanded);

        // see expandInputAes(block x, KeyType& expanded); This version applies 
        // the input expansion to each element, expanbded[i] = expandInputAes(x[i]).
        // However, the expanded input will be in transposed format, i.e.
        // expanded.rows() == 512, && expanded.cols() == divCeil(x.size(), 128)
        static void expandInputAes(span<const block> x, oc::MatrixView<block> expanded);

        // take as input a single 128 bit input and expand it into 512 bit 
        // value with large hamming distance. This version is MPC friendly and corresponds to the strong PRF.
        // Concretely, expanded = G * x where G is a random linear code.
        static void expandInputLinear(block x, KeyType& expanded);

        // see expandInputLinear(block x, KeyType& expanded); This version applies 
        // the input expansion to each element, expanbded[i] = expandInputLinear(x[i]).
        // However, the expanded input will be in transposed format, i.e.
        // expanded.rows() == 512, && expanded.cols() == divCeil(x.size(), 128)
        static void expandInputLinear(span<const block> x, oc::MatrixView<block> expanded);

        // Logiclly, on input v[i], output y[i] = B * v[i]. 
        // However, v should be input in transposed format. Therefore v should
        // have 256 rows and divCeil(y.size(), 128) columns. 
        // requires y.size() == v.rows(),
        //          v.cols() == 2
        static void compressB(
            oc::MatrixView<oc::block> v,
            span<oc::block> y
        );

    };

    inline std::ostream& operator<< (std::ostream& o, AltModPrf::KeyType k)
    {
        o << k[3]
            << "." << k[2]
            << "." << k[1]
            << "." << k[0];
        return o;
    }
}