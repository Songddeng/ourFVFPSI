#pragma once
#include "secure-join/Defines.h"
#include <vector>
#include "cryptoTools/Common/Timer.h"
#include "coproto/Socket/Socket.h"
#include "macoro/task.h"
#include "macoro/macros.h"
#include "secure-join/Perm/Permutation.h"

namespace secJoin
{
    // an XOR sharing of a permutation
    class AdditivePerm 
    {
    public:
        // The XOR shares of the permutation pi.
        std::vector<u32> mShare;

        u64 size() const { return mShare.size(); }

        // check that the shares are actually a permutation
        macoro::task<> validate(coproto::Socket& sock)
        {
            Perm perm(mShare.size());

            co_await sock.send(coproto::copy(mShare));
            co_await sock.recv(perm.mPi);

            for(u64 i = 0; i < perm.mPi.size(); ++i)
            {
                perm.mPi[i] ^= mShare[i];
            }

            perm.validate();
        }
    };
}