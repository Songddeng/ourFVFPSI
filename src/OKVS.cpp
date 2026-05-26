#include "OKVS.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <vector>

OKVS::OKVS(u64 numItems, u64 weight_, u64 ssp, u64 binSize_)
{
    paxos.init(numItems, binSize_, weight_, ssp, volePSI::PaxosParam::GF128, oc::ZeroBlock);
    param = paxos.mPaxosParam;
}

vector<block> OKVS::encode(vector<block> &keys, vector<block> &values, u64 numThreads)
{
    vector<block> E(paxos.size());

    // if (keys.size() != values.size())
    //     throw RTE_LOC;
    PRNG prng(sysRandomSeed());
    paxos.solve<block>(keys, values, E, &prng, numThreads);

    return E;
}

vector<block> OKVS::decode(vector<block> encoding, vector<block> &keys, u64 numThreads)
{
    vector<block> values(keys.size());

    paxos.decode<block>(keys, values, encoding, numThreads);

    return values;
}

u64 OKVS::size()
{
    return paxos.size();
}
