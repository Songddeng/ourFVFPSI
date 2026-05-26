#include "mux.h"
#include <coproto/Socket/Socket.h>
#include <coproto/coproto.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <sys/types.h>
#include <vector>
#include <volePSI/Defines.h>
#include <volePSI/GMW/Circuit.h>
#include <volePSI/GMW/Gmw.h>
#include <volePSI/Paxos.h>
#include <volePSI/config.h>
#include "utils.h"

void ssPEQT(u32 idx, std::vector<block> &input, BitVector &out, Socket &chl, u32 numThreads)
{
    u32 numBins = input.size();
    u64 keyBitLength = 40 + oc::log2ceil(numBins);
    u64 keyByteLength = oc::divCeil(keyBitLength, 8);
    PRNG prng(sysRandomSeed());

    oc::Matrix<u8> mLabel(numBins, keyByteLength);
    for (u32 i = 0; i < numBins; ++i) {
        memcpy(&mLabel(i, 0), &input[i], keyByteLength);
    }

    // call gmw
    auto cir = volePSI::isZeroCircuit(keyBitLength);

    // volePSI::BetaCircuit cir = volePSI::isZeroCircuit(keyBitLength);
    volePSI::Gmw cmp;
    cmp.init(mLabel.rows(), cir, numThreads, idx, prng.get());

    if (idx == 1) {
        cmp.setInput(0, mLabel);
    } else {
        cmp.implSetInput(0, mLabel, mLabel.cols());
    }

    coproto::sync_wait(cmp.run(chl));

    oc::Matrix<u8> mOut;
    mOut.resize(numBins, 1);
    cmp.getOutput(0, mOut);

    // get the final output
    out.resize(numBins);
    for (u32 i = 0; i < numBins; ++i) {
        out[i] = mOut(i, 0) & 1;
    }
    return;
}

MuxSender::MuxSender(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    sender = new osuCrypto::SilentOtExtSender();
    sender->configure(num);
    sender->mMultType = type;

    recver = new osuCrypto::SilentOtExtReceiver();
    recver->configure(num);
    recver->mMultType = type;

    prng = new PRNG(ZeroBlock);
}

MuxSender::~MuxSender()
{
    delete sender;
    delete prng;
}

BitVector MuxSender::mux(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();

    BitVector b0(num);
    ssPEQT(1, u0, b0, *socket, 1);

    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<block> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        correctMessages[i] = messages[i][0] ^ messages[i][1] ^ v0[i];
    }

    coproto::sync_wait(socket->send(correctMessages));

    coproto::sync_wait(recver->receive(b0, res0, *prng, *socket));

    std::vector<block> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    for (u64 i = 0; i < num; i++) {
        res0[i] = res0[i] ^ (b0[i] ? correctMessages1[i] : block(0, 0));
        res0[i] = res0[i] ^ messages[i][0];
        res0[i] = res0[i] ^ (b0[i] ? v0[i] : block(0, 0));
    }

    auto end_comm = socket->bytesReceived() + socket->bytesSent();
    // std::cout << "mux comm: " << (end_comm - curr_comm) / 1024.0 / 1024.0 << " MB " << std::endl;

    return b0;
}

void MuxSender::mux(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0, u64 len)
{
    std::vector<block> temp(v0.size());
    BitVector b0 = mux(u0, v0, temp);

    u64 outputLen = v0.size() / len;
    BitVector b0_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b0_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b0_sum[i] = b0_sum[i] ^ b0[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(recver->receive(b0_sum, message, *prng, *socket));
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res0[i] = res0[i] ^ temp[i * len + j];
        }
        res0[i] = res0[i] ^ message[i] ^ (b0_sum[i] ? messages[i][0] : messages[i][1]);
    }
}

BitVector MuxSender::muxA(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();

    BitVector b0(num);
    ssPEQT(1, u0, b0, *socket, 1);

    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u64> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        u64 mask = low(messages[i][0]) + (v0[i] - 2 * u64(b0[i]) * v0[i]);
        correctMessages[i] = low(messages[i][1]) ^ mask;
    }

    coproto::sync_wait(socket->send(correctMessages));

    std::vector<block> message(num);
    coproto::sync_wait(recver->receive(b0, message, *prng, *socket));

    std::vector<u64> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    for (u64 i = 0; i < num; i++) {
        res0[i] = low(message[i]) ^ (b0[i] ? correctMessages1[i] : 0);
        res0[i] = res0[i] + u64(b0[i]) * v0[i];
        res0[i] = res0[i] - low(messages[i][0]);
    }

    auto end_comm = socket->bytesReceived() + socket->bytesSent();
    // std::cout << "mux comm: " << (end_comm - curr_comm) / 1024.0 / 1024.0 << " MB " << std::endl;

    return b0;
}

void MuxSender::muxA(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0, u64 len)
{
    std::vector<u64> temp(v0.size());
    BitVector b0 = muxA(u0, v0, temp);

    u64 outputLen = v0.size() / len;
    BitVector b0_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b0_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b0_sum[i] = b0_sum[i] ^ b0[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(recver->receive(b0_sum, message, *prng, *socket));
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res0[i] = res0[i] + temp[i * len + j];
        }
        res0[i] = res0[i] + low(message[i]) - (b0_sum[i] ? low(messages[i][0]) : low(messages[i][1]));
    }
}

MuxRecver::MuxRecver(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    sender = new osuCrypto::SilentOtExtSender();
    sender->configure(num);
    sender->mMultType = type;

    recver = new osuCrypto::SilentOtExtReceiver();
    recver->configure(num);
    recver->mMultType = type;

    prng = new PRNG(OneBlock);
}

MuxRecver::~MuxRecver()
{
    delete recver;
    delete prng;
}

BitVector MuxRecver::mux(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1)
{
    BitVector b1(num);
    ssPEQT(0, u1, b1, *socket, 1);

    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    coproto::sync_wait(recver->receive(b1, res1, *prng, *socket));

    std::vector<block> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<block> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        correctMessages[i] = messages[i][0] ^ messages[i][1] ^ v1[i];
    }

    coproto::sync_wait(socket->send(correctMessages));

    for (u64 i = 0; i < num; i++) {
        res1[i] = res1[i] ^ (b1[i] ? correctMessages1[i] : block(0, 0));
        res1[i] = res1[i] ^ messages[i][0];
        res1[i] = res1[i] ^ (b1[i] ? v1[i] : block(0, 0));
    }

    return b1;
}

void MuxRecver::mux(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1, u64 len)
{
    std::vector<block> temp(v1.size());
    BitVector b1 = mux(u1, v1, temp);

    u64 outputLen = v1.size() / len;
    BitVector b1_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b1_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b1_sum[i] = b1_sum[i] ^ b1[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(sender->send(messages, *prng, *socket));
    coproto::sync_wait(recver->receive(b1_sum, message, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res1[i] = res1[i] ^ temp[i * len + j];
        }
        res1[i] = res1[i] ^ message[i] ^ (b1_sum[i] ? messages[i][0] : messages[i][1]);
    }
}

BitVector MuxRecver::muxA(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1)
{
    BitVector b1(num);
    ssPEQT(0, u1, b1, *socket, 1);

    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    std::vector<block> message(num);
    coproto::sync_wait(recver->receive(b1, message, *prng, *socket));

    std::vector<u64> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u64> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        u64 mask = low(messages[i][0]) + (v1[i] - 2 * u64(b1[i]) * v1[i]);
        correctMessages[i] = low(messages[i][1]) ^ mask;
    }

    coproto::sync_wait(socket->send(correctMessages));

    for (u64 i = 0; i < num; i++) {
        res1[i] = low(message[i]) ^ (b1[i] ? correctMessages1[i] : 0);
        res1[i] = res1[i] + u64(b1[i]) * v1[i];
        res1[i] = res1[i] - low(messages[i][0]);
    }

    return b1;
}

void MuxRecver::muxA(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1, u64 len)
{
    std::vector<u64> temp(v1.size());
    BitVector b1 = muxA(u1, v1, temp);

    u64 outputLen = v1.size() / len;
    BitVector b1_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b1_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b1_sum[i] = b1_sum[i] ^ b1[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(sender->send(messages, *prng, *socket));
    coproto::sync_wait(recver->receive(b1_sum, message, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res1[i] = res1[i] + temp[i * len + j];
        }
        res1[i] = res1[i] + low(message[i]) - (b1_sum[i] ? low(messages[i][0]) : low(messages[i][1]));
    }
}