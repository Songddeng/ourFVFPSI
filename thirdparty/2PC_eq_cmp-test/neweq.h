#pragma once

#include "libOTe/include/boost/variant/variant.hpp"
#include "cryptoTools/Common/Timer.h"
// #include "ots.h"
#include "utils.h"
#include "coproto/Common/macoro.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "n1not.h"
#include <boost/type_traits/type_with_alignment.hpp>
#include <cstdint>
#include <macoro/sync_wait.h>
#include <vector>
#include <array>

using namespace std;
using namespace osuCrypto;
using namespace coproto;


template<typename T>
class eq1{
private:
    BitVector bits, share;
    uint8_t* epsilon;
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    PRNG prg;
    T *w, *tmp;
    void vose(BitVector &bits, uint8_t *delta, BitVector &output, int num, int size);
    void initOT(IknpOtExtSender *sender, IknpOtExtReceiver *recver);
public:
    eq1(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    eq1(Role role, AsioSocket &chl, IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    void init(int n, uint32_t ell);
    void offline(int n, uint32_t ell);
    void online(int n, uint32_t ell, T* data, BitVector &output);
    void run(vector<T> data, BitVector &output, uint32_t ell, int numThreads = 1, bool random = true);
};

template<typename T>
class eq2{
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    PRNG prg;
    BitVector r;
    T* t;
    void initOT(IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    void convert_offline(T p, int size);
    void convert_online(T p, int size, BitVector bits, T* output);
public:
    eq2(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver);
    ~eq2() {
    }
    void run(vector<block> &data, BitVector &output, uint32_t ell, int numThreads = 1, bool random = false);
    void online(int size, int len, T* lookupTable, T* delta, T* x, T* output);
};

template<typename T>
eq1<T>::eq1(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver) {
    this->role = role;
    chl = coproto::asioConnect(ip, role == Role::Sender);
    prg.SetSeed(sysRandomSeed());
    initOT(sender, recver);
}

template<typename T>
eq1<T>::eq1(Role role, AsioSocket &chl, IknpOtExtSender *sender, IknpOtExtReceiver *recver) {
    this->role = role;
    this->chl = chl;
    prg.SetSeed(sysRandomSeed());
    initOT(sender, recver);
}

template<typename T>
void eq1<T>::initOT(IknpOtExtSender *sender_, IknpOtExtReceiver *recver_) {
    if (role == Role::Sender) {
        if (sender_ != NULL) {
            this->sender = sender_;
        } else {
            this->sender = new IknpOtExtSender();

            DefaultBaseOT base;
            BitVector bv(sender->baseOtCount());
            std::vector<block> base_msg(sender->baseOtCount());

            bv.randomize(prg);
            cp::sync_wait(base.receive(bv, base_msg, prg, chl));
            sender->setBaseOts(base_msg, bv);
        }
    } else {
        if (recver_) {
            this->recver = recver_;
        } else {
            this->recver = new IknpOtExtReceiver();
            DefaultBaseOT base;
            std::vector<std::array<block, 2>> base_msg(recver->baseOtCount());
            cp::sync_wait(base.send(base_msg, prg, chl));

            recver->setBaseOts(base_msg);
        }
    }
}

template<typename T>
void eq1<T>::offline(int n, uint32_t ell2) {
    if (role == Role::Sender) {
        prg.get(epsilon, n);
        
        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            epsilon[i] %= ell2;
            bits[i*ell2 + epsilon[i]] = 1;
        }
    } 
    vose(bits, epsilon, share, n, ell2);
}

template<typename T>
void eq1<T>::online(int n, uint32_t ell2, T* data, BitVector &output) {
    coproto::span<T> ws(w, n), tmps(tmp, n);
    if (role == Role::Sender) {
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            w[i] = (data[i] + epsilon[i]) % ell2;
        }
        sync_wait(chl.recv(tmps));
        sync_wait(chl.send(ws));
    } else {
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            ws[i] = (epsilon[i] + ell2 - data[i]) % ell2;
        }
        sync_wait(chl.send(ws));
        sync_wait(chl.recv(tmps));
    }
    
    // //#pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        output[i] = share[i*ell2 + ((w[i] + tmp[i]) % ell2)];
    }
}

template<typename T>
void eq1<T>::init(int n, uint32_t ell2) {
    epsilon = new uint8_t[n]();
    w = new T[n]();
    tmp = new T[n]();
    int sumsize = n * ell2;
    bits.reset(sumsize);
}

template<typename T>
void eq1<T>::vose(BitVector &bits, uint8_t *delta, BitVector &output, int nums, int size) {
    int simd_size = 16;
    uint64_t** seed = new uint64_t*[nums];
    for(int i = 0; i < nums; ++i) {
        seed[i] = new uint64_t[size]();
    }
    int simd_num = (size + 15)/simd_size;
    
    NCN1OT<uint64_t> ot(role, nums, size, sender, recver, chl);

    BitVector u;

    int sizebyte = size / 8;

    if (role == Role::Sender) {
        ot.send(seed);
        
        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            int tmp_i = i * size;
            int tmp, tmp_k0, tmp_jk;
            BitVector resu(size), resv(size);
            BitVector temp0(size);
            
            for (int j = 0; j < size; ++j) {
                block seed_one = toBlock(0, seed[i][j]);
                
                PRNG prng;
                prng.SetSeed(seed_one);
                prng.get<uint8_t>(temp0.data(), temp0.sizeBytes());

                resu ^= temp0;

                BitVector temp1;
                temp1.copy(temp0, j, size-j);
                temp1.append(temp0, j);
                resv ^= temp1;
                
            }
            output.append(resu);
            u.append(resv);
        }
        u ^= bits;

        sync_wait(chl.send(u));
        sync_wait(chl.flush());
    } else {
        ot.recv(seed, delta);
        
        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            int tmp_i = i * size;
            int tmp, tmp_k0, tmp_jk;
            BitVector res(size);
            BitVector temp0(size);
            
            for (int j = 0; j < size; ++j) {
                if (j == delta[i]) continue;
                block seed_one = toBlock(0, seed[i][j]);
                prg.SetSeed(seed_one);
                prg.get<uint8_t>(temp0.data(), temp0.sizeBytes());
                
                res ^= temp0;
                
                int tmp_jk = (j+size-delta[i])%size;
                BitVector temp1;
                temp1.copy(temp0, tmp_jk, size-tmp_jk);
                temp1.append(temp0, tmp_jk);

                res ^= temp1;
            }
            output.append(res);
        }
        u.reset(nums*size);
        
        sync_wait(chl.recv(u));
        sync_wait(chl.flush());
        
        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            int tmp_i = i*size;
            for (int j = 0; j < size; ++j) {
                output[tmp_i + j] = u[tmp_i + ((j + size - delta[i])%size)] ^ output[tmp_i + j];
            }
        }
    }
}

template<typename T>
eq2<T>::eq2(Role role, string ip, IknpOtExtSender *sender, IknpOtExtReceiver *recver) {
    this->role = role;
    chl = coproto::asioConnect(ip, role == Role::Sender);
    prg.SetSeed(sysRandomSeed());
    initOT(sender, recver);
}

template<typename T>
void eq2<T>::initOT(IknpOtExtSender *sender_, IknpOtExtReceiver *recver_) {
    if (role == Role::Sender) {
        if (sender_ != NULL) {
            this->sender = sender_;
        } else {
            this->sender = new IknpOtExtSender();

            DefaultBaseOT base;
            BitVector bv(sender->baseOtCount());
            std::vector<block> base_msg(sender->baseOtCount());

            bv.randomize(prg);
            cp::sync_wait(base.receive(bv, base_msg, prg, chl));
            sender->setBaseOts(base_msg, bv);
        }
    } else {
        if (recver_) {
            this->recver = recver_;
        } else {
            this->recver = new IknpOtExtReceiver();
            DefaultBaseOT base;
            std::vector<std::array<block, 2>> base_msg(recver->baseOtCount());
            cp::sync_wait(base.send(base_msg, prg, chl));

            recver->setBaseOts(base_msg);
        }
    }
}

template<typename T>
void eq2<T>::run(vector<block> &data, BitVector &output, uint32_t ell, int numThreads, bool random) {
    if (random)
        prg.get(data.data(), data.size());
    int n = data.size();
    int size = n * ell;
    int p = getmod(ell);
    
    BitVector bits;

    for (int i = 0; i < n; ++i) {
        bits.append((u8*)data[i].data(), ell);
    }
    

    t = new T[size]();
    r.reset(size);
    T *share = new T[size]();
    T *addshare = new T[n]();

    eq1<T> eq11(role, chl, sender, recver);
    eq11.init(n, p);
    
    Timer timer;
    Timer::timeUnit offline_start, offline_end, online_start, online_end;

    cout << "=====offline start=====" << endl;
    u64 com_off_begin = chl.bytesReceived() + chl.bytesSent();
    offline_start = timer.setTimePoint("offline_start");

    convert_offline(p, size);
    eq11.offline(n, p);

    offline_end = timer.setTimePoint("offline_end");
    u64 com_off_end = chl.bytesReceived() + chl.bytesSent();
    
    cout << "=====offline end=====" << endl;
    sync_wait(sync(chl, role));
    //==========online===========
    cout << "=====online start=====" << endl;
    u64 com_begin = chl.bytesReceived() + chl.bytesSent();
    online_start = timer.setTimePoint("online_start");

    convert_online(p, size, bits, share);

    
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < ell; ++j) {
            addshare[i] = (addshare[i] + share[i*ell + j]) % p;
        }
    }
    if (role == Role::Receiver) {
        for (int i = 0; i < n; ++i) {
            addshare[i] = (p - addshare[i]) % p;
        }
    }
    delete[] share;


    eq11.online(n, p, addshare, output);
    cout << "=====online end=====" << endl;
    online_end = timer.setTimePoint("online_end");

}

template<typename T>
void eq2<T>::convert_offline(T p, int size) {
    prg.get(r.data(), r.sizeBytes());
    if (role == Role::Sender) {
        T *pad = new T[2*size];
        coproto::span<T> pat(pad, 2*size);
        prg.get(t, size);
        for (int i = 0; i < size; ++i) {
            t[i] %= p;
        }
        std::vector<std::array<block, 2>> data(size);
        sync_wait(sender->send(data, prg, chl));

        //#pragma omp parallel for
        for (int64_t i = 0; i < size; ++i) {
            pat[2*i] = *(T*)(data[i][0].data()) ^ ((t[i] - r[i] + p) % p);
            pat[2*i+1] = *(T*)(data[i][1].data()) ^ ((t[i] - 1 + r[i] + p) % p);
        }

        sync_wait(chl.send(pat));
        delete pad;
    } else {
        vector<block> data(size);
        sync_wait(recver->receive(r, data, prg, chl));
    
        T *pad = new T[2*size];
        coproto::span<T> pat(pad, 2 * size);
        sync_wait(chl.recv(pat));

        //#pragma omp parallel for
        for (int i = 0; i < size; ++i) {
            t[i] = (p - (*(T*)data[i].data() ^ pat[2*i+r[i]])) % p;
        }
    }
}

template<typename T>
void eq2<T>::convert_online(T p, int size, BitVector bits, T* output) {
    BitVector w(size), tmp(size);
    const T pp = p * 2;
    // //#pragma omp parallel for
    for (int i = 0; i < size; ++i) {
        w[i] = bits[i] ^ r[i];
    }

    if (role == Role::Sender) {
        sync_wait(chl.send(w));
        sync_wait(chl.recv(tmp));

        // //#pragma omp parallel for
        for (int i = 0; i < size; ++i) {
            w[i] = w[i] ^ tmp[i];
            output[i] = ((T)w[i] + t[i] - ((2*w[i]*t[i]) % p) + p) % p;
        }

    } else {
        sync_wait(chl.recv(tmp));
        sync_wait(chl.send(w));

        // //#pragma omp parallel for
        for (int i = 0; i < size; ++i) {
            output[i] = (t[i] - ((2*(w[i] ^ tmp[i]) * t[i]) % p) + p) % p;
        }
    }
}

