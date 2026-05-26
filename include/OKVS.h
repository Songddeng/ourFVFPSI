#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>
#include <cstring>
#include <vector>
#include "volePSI/Paxos.h"

using namespace oc;
using namespace osuCrypto;
using namespace std;

class OKVS {
public:
    OKVS(u64 numItems, u64 weight_ = 3, u64 ssp = 40, u64 binSize_ = 1 << 14);

    vector<block> encode(vector<block> &keys, vector<block> &values, u64 numThreads = 1);

    vector<block> decode(vector<block> encoding, vector<block> &keys, u64 numThreads = 1);

    u64 size();

private:
    volePSI::Baxos paxos;
    volePSI::PaxosParam param;
};
