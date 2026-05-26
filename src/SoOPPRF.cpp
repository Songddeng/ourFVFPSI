#include "SoOPPRF.h"
#include <coproto/Common/macoro.h>
#include "SoOPRF.h"

SoOPPRFSender::SoOPPRFSender(uint64_t num_, uint64_t num_kv_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_)
    : SoOPRFSender(num_, numThreads_, useOle_, socket_)
{
    okvs = new OKVS(num_kv_);
}

SoOPPRFSender::~SoOPPRFSender()
{
    delete okvs;
}

void SoOPPRFSender::OPPRF(std::vector<oc::block> &keys, std::vector<oc::block> &values, std::vector<oc::block> &y0)
{
    SoOPRFSender::OPRF(y0);

    std::vector<oc::block> values_masked(values);

    AltModPrf prf(SoOPRFSender::getKey());
    std::vector<block> prf_value(keys.size());
    prf.eval(keys, prf_value);

    for (u64 i = 0; i < values.size(); ++i) {
        values_masked[i] = values[i] ^ prf_value[i];
    }

    auto encoding = okvs->encode(keys, values_masked);

    coproto::sync_wait(socket->send(encoding));
}

void SoOPPRFSender::OPPRF(std::vector<oc::block> encoding, std::vector<oc::block> &y0)
{
    SoOPRFSender::OPRF(y0);

    coproto::sync_wait(socket->send(encoding));
}

SoOPPRFRecver::SoOPPRFRecver(uint64_t num_, uint64_t num_kv_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_)
    : SoOPRFRecver(num_, numThreads_, useOle_, socket_)
{
    okvs = new OKVS(num_kv_);
}

SoOPPRFRecver::~SoOPPRFRecver()
{
    delete okvs;
}

void SoOPPRFRecver::OPPRF(std::vector<oc::block> &keys, std::vector<oc::block> &y1)
{
    std::vector<oc::block> tmp(keys.size());

    SoOPRFRecver::OPRF(keys, tmp);

    std::vector<oc::block> encoding(okvs->size());

    coproto::sync_wait(socket->recv(encoding));

    auto d = okvs->decode(encoding, keys);

    for (u64 i = 0; i < keys.size(); i++) {
        y1[i] = d[i] ^ tmp[i];
    }
}