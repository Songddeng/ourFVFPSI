#pragma once

#include "libOTe/include/boost/variant/variant.hpp"
#include "cryptoTools/Common/Timer.h"
#include "utils.h"
#include "coproto/Common/macoro.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "n1not.h"
#include <boost/type_traits/type_with_alignment.hpp>
#include <chrono>
#include <cstdint>
#include <macoro/sync_wait.h>
#include <vector>
#include <array>
#include "coeff.h"

using namespace std;
using namespace osuCrypto;
using namespace coproto;

struct CmpProfile {
    double offline_ms = 0.0;
    double online_ms = 0.0;
    uint64_t offline_comm_bytes = 0;
    uint64_t online_comm_bytes = 0;
};

template<typename T>
class cmp1{
private:
    BitVector bits;
    T *m;
    T *s;
    T *idx;
    T *a;
    T *c;
    T *w;
    BitVector r;
    T* t;
    T p;
    
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    KkrtNcoOtSender *nsender;
    KkrtNcoOtReceiver *nrecver;
    SilentVoleReceiver<Zp, Zp, MyCoeffCtx> *volereceiver;
    SilentVoleSender<Zp, Zp, MyCoeffCtx> *volesender;
    PRNG prg;
    int n, ell;
    CmpProfile *profile = nullptr;
    void initOT();
    void convert_offline(T p, int size);
    void convert_online(T p, int size, BitVector bits, T* output);
    void OLE(T* a1, T* c1);

    void permute(vector<T> choice);
    void VOLE();
    
    void oss_offline(vector<T> &pi, vector<T> &pi1);
    void oss_online(vector<T> &pi1, BitVector &res);
    void pre_sum(int p);
    void get_index(int n, uint32_t ell, BitVector &res);
public:
    cmp1(Role role, string ip, int n, int ell, CmpProfile *profile = nullptr);
    void run(vector<block> data, BitVector &output, uint32_t ell, int numThreads = 1, bool random = false);
};

template<typename T>
cmp1<T>::cmp1(Role role, string ip, int n, int ell, CmpProfile *profile) {
    this->role = role;
    this->n = n;
    this->ell = ell;
    this->profile = profile;
    p = getmod(ell);
    Zp::p = p;
    chl = coproto::asioConnect(ip, role == Role::Sender);
    // prg.SetSeed(sysRandomSeed());
    prg.SetSeed(sysRandomSeed());

    Timer timer;
    auto init_start = timer.setTimePoint("cmp_init_start");
    u64 init_comm_begin = chl.bytesReceived() + chl.bytesSent();
    initOT();
    auto init_end = timer.setTimePoint("cmp_init_end");
    u64 init_comm_end = chl.bytesReceived() + chl.bytesSent();

    if (this->profile) {
        this->profile->offline_ms += std::chrono::duration_cast<std::chrono::microseconds>(init_end - init_start).count() / 1000.0;
        this->profile->offline_comm_bytes += init_comm_end - init_comm_begin;
    }
}

template<typename T>
void cmp1<T>::run(vector<block> data, BitVector &output, uint32_t ell, int numThreads, bool random) {
    if (random)
        prg.get(data.data(), data.size());
    int n = data.size();

    int numsize = n * ell;
    int sumsize = n * (ell + 2);
    int allsize = n * (ell + 2 + (ell));

    bits.reset(0);
    for (int i = 0; i < n; ++i) {
        BitVector temp((u8*)data[i].data(), ell);
        for (int j = ell - 1; j >= 0; --j) {
            bits.pushBack(temp[j]);
        }
    }
    
    vector<T> pi(allsize), pi1(allsize);

    m = new T[numsize]();
    s = new T[sumsize]();
    a = new T[allsize]();
    c = new T[allsize]();
    w = new T[allsize]();
    idx = new T[n * (ell + 1)]();
    r.reset(numsize);
    t = new T[numsize];

    Timer timer;
    Timer::timeUnit offline_start, offline_end, online_start, online_end;

    cout << "=====offline start=====" << endl;
    u64 com_off_begin = chl.bytesReceived() + chl.bytesSent();
    offline_start = timer.setTimePoint("offline_start");

    convert_offline(p, numsize);
    oss_offline(pi, pi1);

    offline_end = timer.setTimePoint("offline_end");
    
    cout << "=====offline end=====" << endl;
    sync_wait(sync(chl, role));
    u64 com_sync_end = chl.bytesReceived() + chl.bytesSent();
    if (profile) {
        profile->offline_ms += std::chrono::duration_cast<std::chrono::microseconds>(offline_end - offline_start).count() / 1000.0;
        profile->offline_comm_bytes += com_sync_end - com_off_begin;
    }
    //==========online===========
    cout << "=====online start=====" << endl;
    u64 com_begin = chl.bytesReceived() + chl.bytesSent();
    online_start = timer.setTimePoint("online_start");

    convert_online(p, numsize, bits, m);
    pre_sum(p);

    if (role == Role::Sender) {
        get_index(n, ell, output);
    }
    oss_online(pi1, output);

    online_end = timer.setTimePoint("online_end");
    u64 com_end = chl.bytesReceived() + chl.bytesSent();

    if (profile) {
        profile->online_ms += std::chrono::duration_cast<std::chrono::microseconds>(online_end - online_start).count() / 1000.0;
        profile->online_comm_bytes += com_end - com_begin;
    }

    cout << "=====online end=====" << endl;
}

template<typename T>
void cmp1<T>::pre_sum(int p) {
    int ell2 = ell + 2;
    if (role == Role::Sender) {
        for (int i = 0; i < n; ++i) {
            int tmpi = i * ell2;
            int tmpii = i * ell;
            int pres = m[tmpii];
            s[tmpi] = (1 - pres + p) % p;
            for (int j = 1; j < ell; ++j) {
                s[tmpi + j] = (pres + 1 - m[tmpii+j] + p) % p;
                pres = (pres + m[tmpii+j]) % p;
            }
            //s[tmpi + ell] = (pres + 1) % p;
            s[tmpi + ell] = (pres - 1 + p) % p; //add 0
            s[tmpi + ell + 1] = 1;
        }
    } else {
        for (int i = 0; i < n; ++i) {
            int tmpi = i * ell2;
            int tmpii = i * ell;
            auto pres = m[tmpii];
            s[tmpi] = (p - pres) % p;
            for (int j = 1; j < ell; ++j) {
                s[tmpi + j] = (pres + p - m[tmpii+j]) % p;
                pres = (pres + m[tmpii+j]) % p;
            }
            //s[tmpi + ell] = (pres - 1 + p) % p;
            s[tmpi + ell] = (pres + 1) % p; //add 1
            s[tmpi + ell + 1] = 1;
        }
    }
}

// res是n*size个，对bits判断每size里面判断是0最少还是1最少，返回0或1
// 修改为随机选择0或者1
// 之前的方案是选择最少的，这样可以把整体查询次数降低到ell/2次
// 现在修改为ell + 1 次
template<typename T>
void cmp1<T>::get_index(int n, uint32_t ell, BitVector &res) {
    for (int i = 0; i < n; ++i) {
        // int cnt = 0;
        int tmp_i = i * ell;
        int tmp_ii = i * (ell + 1);
        int mxii = tmp_ii + (ell + 1);
        // for (int j = tmp_i; j < tmp_i + ell; ++j) {
        //     cnt += bits[j];
        // }
        // if (cnt*2 >= ell+1) {
        //     res[i] = 0;
        // } else {
        //     res[i] = 1;
        // }
        uint8_t randomchoose = prg.get<uint8_t>() % 2;
        res[i] = randomchoose;
        for (int j = 0; j < ell; ++j) {
            if (bits[tmp_i + j] == res[i]) {
                idx[tmp_ii++] = j;
            }
        }
        while (tmp_ii < mxii) {
            idx[tmp_ii++] = ell + 1;
        }

    }
}

template<typename T>
void cmp1<T>::initOT() {
    bool maliciousSecure = false;
    uint64_t statSecParam = 40;
    uint64_t inputBitCount = log2(ell+2+ell) + 1;
    if (role == Role::Sender) {
        this->sender = new IknpOtExtSender();

        DefaultBaseOT base;
        BitVector bv(sender->baseOtCount());
        std::vector<block> base_msg(sender->baseOtCount());

        bv.randomize(prg);
        cp::sync_wait(base.receive(bv, base_msg, prg, chl));
        sender->setBaseOts(base_msg, bv);

        this->volereceiver = new SilentVoleReceiver<Zp, Zp, MyCoeffCtx>();
        volereceiver->mLpnMultType = DefaultMultType;
        volereceiver->configure(n * (ell+1));

        nrecver = new KkrtNcoOtReceiver;
        nrecver->configure(maliciousSecure, statSecParam, inputBitCount);
        sync_wait(nrecver->genBaseOts(prg, chl));
    } else {
        this->recver = new IknpOtExtReceiver();
        DefaultBaseOT base;
        std::vector<std::array<block, 2>> base_msg(recver->baseOtCount());
        cp::sync_wait(base.send(base_msg, prg, chl));

        recver->setBaseOts(base_msg);

        this->volesender = new SilentVoleSender<Zp, Zp, MyCoeffCtx>();
        volesender->mLpnMultType = DefaultMultType;
        volesender->configure(n * (ell+1));

        nsender = new KkrtNcoOtSender();
        nsender->configure(maliciousSecure, statSecParam, inputBitCount);

        sync_wait(nsender->genBaseOts(prg, chl));
    }
}


template<typename T>
void cmp1<T>::convert_offline(T p, int size) {
    r.randomize(prg);
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
void cmp1<T>::convert_online(T p, int size, BitVector bits, T* output) {
    BitVector w(size), tmp(size);

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

template<typename T>
void cmp1<T>::OLE(T* a1, T* c1) {
    int ellp = log2(ell)+1;

    int ell2 = ell+1;
    int numOTs = n * ell2 * ellp;
    int numsize = n * ell2;
    prg.get<T>(a1, numsize);
    for (int i = 0; i < numsize; ++i) {
        a1[i] = a1[i] % p;
        if (role == Role::Sender && a1[i] == 0) {
            do {
                prg.get<T>(a1+i, 1);
                a1[i] = a1[i] % p;
            } while (a1[i] == 0);
        }
    }
    if (role == Role::Sender) {
        T *r = new T[numOTs];
        prg.get<T>(r, numOTs);
        for (int i = 0; i < numOTs; ++i) {
            r[i] = r[i] % p;
        }
        std::vector<std::array<block, 2>> messages(numOTs);
        T *pad = new T[numOTs * 2]();
        sender->send(messages, prg, chl);

        //#pragma omp parallel for
        for (int i = 0; i < numOTs; ++i) {
            int tmpi = i / ellp;
            int tti = i % ellp;
            pad[2*i] = *(T*)messages[i].data() ^ r[i];
            pad[2*i+1] = *(T*)messages[i].data() ^ (uint8_t)(((uint16_t)(a1[tmpi]) * (1 << (i%ellp)) + r[i]) % p);
            c1[tmpi] = (c1[tmpi] + p - r[i]) % p;
        }
        coproto::span<T> pat(pad, numOTs*2);
        sync_wait(chl.send(pat));
        delete[] pad;
        delete[] r;
    } else {
        BitVector choice;
        vector<block> message(numOTs);
        T *pad = new T[numOTs*2]();
        // choice.reserve(numOTs);
        for (int i = 0; i < numsize; ++i) {
            choice.append(a1+i, ellp);
        }
        recver->receive(choice, message, prg, chl);
        coproto::span<T> pat(pad, numOTs*2);
        sync_wait(chl.recv(pat));

        //#pragma omp parallel for
        for (int i = 0; i < numOTs; ++i) {
            int tmpi = i/ellp;
            c1[tmpi] = (c1[tmpi] + (*(T*)message[i].data() ^ pat[2*i+choice[i]])) % p;
        }
        delete[] pad;
    }
}

template<typename T>
void cmp1<T>::permute(vector<T> pi) {
    if (role == Role::Sender) {
        int inum = ell + 2 + (ell);
        int sumsize = pi.size();
        Matrix<T> messages(sumsize, ell+2+(ell));
        vector<block> message(sumsize);
        // one out of n

        sync_wait(nrecver->init(sumsize, prg, chl));

        //#pragma omp parallel for
        for(int i = 0; i < sumsize; ++i) {
            block tmp = toBlock(0, pi[i]);
            nrecver->encode(i, &tmp, message.data()+i, sizeof(T));
        }

        sync_wait(nrecver->sendCorrection(chl, sumsize));
        sync_wait(chl.recv(messages));

        //#pragma omp parallel for
        for (int i = 0; i < sumsize; ++i) {
            int tmpi = (i / inum);
            tmpi *= inum;
            w[i] = (c[tmpi + pi[i]] + (*(T*)message[i].data() ^ messages(i, pi[i]))) % p;
        }

    } else {
        int inum = ell + 2 + (ell);
        int sumsize = n * inum;
        prg.get<T>(w, sumsize);
        for (int i = 0; i < sumsize; ++i) {
            w[i] = w[i] % p;
        }
        Matrix<T> messages(sumsize, inum);
        
        sync_wait(nsender->init(sumsize, prg, chl));
        sync_wait(nsender->recvCorrection(chl, sumsize));

        block tmpm;
        //#pragma omp parallel for
        for (int i = 0; i < sumsize; ++i) {
            int tmpi = i / inum;
            tmpi *= inum;
            for (int j = 0; j < inum; ++j) {
                T tmpv = (c[tmpi+j] + p - w[i])  % p;
                nsender->encode(i, &j, &tmpm, sizeof(T));
                messages(i, j) = *(T*)tmpm.data() ^ tmpv;
            }
        }

        sync_wait(chl.send(messages));

    }
}


template<typename T>
void cmp1<T>::oss_offline(vector<T> &pi, vector<T> &pi1) {
    int ell2 = ell+1;
    int ellh = ell+1;
    int numVole = n * ellh;
    int single = ell2+ellh;
    T *a1 = new T[n*(ell2)]();
    T *c1 = new T[n*(ell2)]();
    if (role == Role::Sender) {
        pi.resize(n *single), pi1.resize(n*single);
        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            int tmpi = i * single;
            int tmpii = tmpi + single;
            std::random_device rd;
            std::mt19937 gen(rd());
            std::iota(pi.begin() + tmpi, pi.begin() + tmpii, 0);
            std::shuffle(pi.begin() + tmpi, pi.begin() + tmpii, gen);
            for (int j = 0; j < single; ++j) {
                pi1[tmpi+pi[tmpi+j]] = j;
            }
        }
    }

    OLE(a1, c1);

    if (role == Role::Sender) {
        // vole 可能会生成 a=0，需要处理。
        AlignedUnVector<Zp> a2(numVole), c2(numVole);
        sync_wait(volereceiver->silentReceive(a2, c2, prg, chl));

        // 消去a = 0的情况
        vector<T> ap(numVole); 
        prg.get<T>(ap.data(), numVole);
        for (int i = 0; i < numVole; ++i) {
            ap[i] = ap[i] % p;
            if (ap[i] == 0) {
                do {
                    prg.get<T>(ap.data()+i, 1);
                    ap[i] = ap[i] % p;
                } while (ap[i] == 0);
            }
            a2[i].value = (p - ap[i] + a2[i].value) % p;
        }
        sync_wait(chl.send(a2));

        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            memcpy(a+i*single, a1+i*(ell+1), ell2);
            memcpy(c+i*single, c1+i*(ell+1), ell2);
            memcpy(a+i*single+ell2, &ap[i*ellh], ellh);
            memcpy(c+i*single+ell2, &c2[i*ellh], ellh);
        }
    } else {
        AlignedUnVector<Zp> ap(numVole), c2(numVole);
        T a2_v = prg.get<T>();
        while (a2_v % p == 0) {
            a2_v = prg.get<T>();
        }
        Zp a2{a2_v % p};
        

        sync_wait(volesender->silentSend(a2, c2, prg, chl));
        sync_wait(chl.recv(ap));
        
        //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            int tmpi = i * single;
            int tmpi1 = tmpi + ell2;
            memcpy(a+tmpi, a1+i*(ell+1), ell2);
            memcpy(c+tmpi, c1+i*(ell+1), ell2);
            
            int tmpj = i * ellh;
            for (int j = 0; j < ellh; ++j) {
                c[tmpi1+j] = (p - ((c2[tmpj + j].value + (ap[tmpj+j].value * (a2.value)) % p ) % p) % p) % p;
                // c[tmpi1+j] = (p - (c2[tmpj + j].value)) % p;
                a[tmpi1+j] = a2.value;
            }
        }
    }

    permute(pi);
}

template<typename T>
void cmp1<T>::oss_online(vector<T> &pi1, BitVector &res) {
    int ell2 = ell + 2;
    int ellh = ell + 1;
    int single = ell + 1 + ellh;
    int sumsize = n * ell2, halfsize = n * (ellh);
    T* d = new T[halfsize]();
    T* index = new T[halfsize];
    coproto::span<T> dp(d, halfsize), ip(index, halfsize);
    
    if (role == Role::Sender) {
        T* a2 = new T[n * single];
        T* w2 = new T[n * single];
        T* s2 = new T[n * (ell + 2)];
        coproto::span<T> a2p(a2, n * single);
        coproto::span<T> w2p(w2, n * single);
        coproto::span<T> s2p(s2, n * (ell + 2));
        sync_wait(chl.recv(a2p));
        sync_wait(chl.recv(w2p));
        sync_wait(chl.recv(s2p));

        T* Y = new T[sumsize]();
        coproto::span<T> Yp(Y, sumsize);
        sync_wait(chl.recv(Yp));

        int tmpi, tmpj, tmpjj, tmphi, tmpsi;

        
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            int firstj = ell + 1 + ell;
            tmpi = i * ell2; // 
            tmphi = i * (ell + 1);  // ell + 1 个查询
            tmpsi = i * single;  // ell + 2 + ell 个pi
            for (int j = 0; j < ell + 1; ++j) {
                // tmpj = tmphi + j;
                if (idx[tmphi + j] != ell + 1) {
                    auto tmpsij = tmpsi + idx[tmphi + j];
                    auto tmpij = tmpi + idx[tmphi + j];
                    
                    index[tmphi + j] = pi1[tmpsi + idx[tmphi + j]];
                    d[tmphi + j] = ((a[tmpsij] * (s[tmpij] + Y[tmpij]) % p) %p + p - w[tmpsi + pi1[tmpsij]]) % p;
                } else {
                    firstj = min(firstj, j);
                    
                    auto tmpsij = tmpsi + j - firstj + ell + 1;
                    auto tmpij = tmpi + ell2 - 1;
                    
                    index[tmphi + j] = pi1[tmpsij];
                    d[tmphi + j] = ((a[tmpsij] * ((s[tmpij] + Y[tmpij]) % p)) %p + p - w[tmpsi + pi1[tmpsij]]) % p;
                }
            }
        }
        sync_wait(chl.send(dp));
        sync_wait(chl.send(ip));
    } else {
        coproto::span<T> a2p(a, n * single);
        coproto::span<T> w2p(w, n * single);
        coproto::span<T> s2p(s, n * (ell + 2));
        sync_wait(chl.send(a2p));
        sync_wait(chl.send(w2p));
        sync_wait(chl.send(s2p));
        for (int i = 0; i < n; ++i) {
            int tmpi = i * ell2;
            int tmpa = i * single;
            for (int j = 0; j < ell + 2; ++j) {
                s[tmpi+j] = (s[tmpi+j] + a[tmpa + j]) % p;
            }
        }
        coproto::span<T> sp(s, sumsize);
        sync_wait(chl.send(sp));

        
        sync_wait(chl.recv(dp));
        sync_wait(chl.recv(ip));

        int tmpi, tmpj, tmphi, tmpsi;
        // //#pragma omp parallel for
        for (int i = 0; i < n; ++i) {
            tmphi = i * (ell + 1);
            tmpsi = i * (single);
            for (int j = 0; j < ell + 1; ++j) {
                tmpj = tmphi + j;
                dp[tmphi + j] = (dp[tmphi + j] + p - w[tmpsi+ip[tmphi + j]]) % p;
                if (dp[tmpj] == 0) {
                    res[i] = 1;
                    break;
                }
            }
            res[i] ^= 1;
        }
    }
}
