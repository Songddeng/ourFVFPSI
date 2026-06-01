#pragma once
#include <omp.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/block.h>
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "coproto/Socket/AsioSocket.h"
#include "libOTe/Base/BaseOT.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/Common/span.h"
// #include "utils.h"

using namespace std;
using namespace osuCrypto;
using namespace coproto;


template<typename T>
class NCN1OT {
public:
    // NCN1OT() = default;

    NCN1OT(Role role, int nums, int length, IknpOtExtSender *sender, IknpOtExtReceiver *recver, AsioSocket &chl) {
        this->nums = nums;
        this->length = length;
        this->sender = sender;
        this->recver = recver;
        this->chl = chl;
        this->role = role;
        
        prg.SetSeed(sysRandomSeed());
        // prg.SetSeed(toBlock(0, 0));
    }

    ~NCN1OT() {
        // delete ferretcot;
    }

    void send(T** data) {
        int depth = log2(length) + 1;
        int numOTs = nums * depth;
        T **seeds = new T*[nums];
        T *str0 = new T[nums*depth];
        T *str1 = new T[nums*depth];
        //#pragma omp parallel for schedule(dynamic)
        for (int i = 0; i < nums; ++i) {
            OblivSetup(length, seeds + i, str0+(i*depth), str1+(i*depth));
        }

        send_ot(str0, str1, nums*depth);

        //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            Expand(length, -1, *(seeds + i), data[i]);
        }
    }

    void recv(T **data, uint8_t *epsilon) {
        int depth = log2(length) + 1;
        int numOTs = nums * depth;
        // T **seeds = (T **)malloc(nums * sizeof(T *));
        T **seeds = new T*[nums];
        // bool *chosen_bit = new bool[nums*depth];
        BitVector chosen_bit(nums*depth);
        T *temp = new T[nums*depth];
        
        // PRNG prg;
        prg.get(epsilon, nums*sizeof(epsilon[0]));


        // //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            OblivSetup(length, seeds + i, NULL, NULL);
            int tmp_i = i * depth;
            epsilon[i] = epsilon[i] % length;
            uint64_t x = epsilon[i];
            for (int j = depth-1; j >= 0; --j) {
                chosen_bit[tmp_i + j] = (x & 1) ^ 1;
                x >>= 1;
            }
        }
        
        recv_ot(temp, chosen_bit, nums*depth);
        
        // //#pragma omp parallel for
        for (int i = 0; i < nums; ++i) {
            memcpy(*(seeds+i), temp+i*depth, depth*sizeof(T));
            // for (int j = 0; j < depth; ++j) {
            // }
            Expand(length, epsilon[i], *(seeds + i), data[i]);
        }
    }
private:
    // int party;
    Role role;
    AsioSocket chl;
    IknpOtExtSender *sender;
    IknpOtExtReceiver *recver;
    PRNG prg;

    int nums, length;
    void DLenPRG(T seed, T *out) {
        block temp = toBlock(0, seed);
        AES aes(temp);
        block res, pt = AllOneBlock;

        aes.ecbEncBlocks(&AllOneBlock, 1, &res);
        memcpy(out, &res, 2*sizeof(T));
    }

    void OblivSetup(uint64_t length, T **seeds, T *str0, T *str1) {
        int depth = int(log2(length)) + 1;
        if (role == Role::Sender) {
            *seeds = new T;

            // generate root
            prg.get(*seeds, 1);
            // preparing data for the following ote
            memset(str0, 0x00, depth * sizeof(T));
            memset(str1, 0x00, depth * sizeof(T));

            PrepareCorrelation(0, depth, **seeds, str0, str1);
        } else {
            *seeds = new T[depth];
            // parse input i to bool vector
        }
    }

    void SimpleExpand(int cur_depth, int depth, int index, T seed, T *v) {
        T next_seeds[2];
        DLenPRG(seed, next_seeds);

        if (cur_depth == depth - 1) {  
            if (index < length)
            v[index] = next_seeds[0];
            if (index + 1 < length)
            v[index + 1] = next_seeds[1];
            return;
        }

        int offset = 1 << (depth - cur_depth - 1);
        SimpleExpand(cur_depth + 1, depth, index, next_seeds[0], v);
        SimpleExpand(cur_depth + 1, depth, index + offset, next_seeds[1], v);
    }

    int CheckOnPath(T x, T y) {
        return x==y;
    }

    void PunctureExpand(int depth, uint64_t x, T *seeds, T *v) {
        int size = 0;
        int cur_depth = 1;

        bool bits[depth];

        T seed, agg_mask;
        T next_seeds[2];

        std::deque<T> q;

        for (int i = depth - 1; i >= 0 ; i--) {
            bits[i] = (x & 1) ^ 1;
            x >>= 1;
        }

        int path = bits[0];
        
        if (bits[0]) {
            q.push_back(0);
            q.push_back(*seeds);
        } else {
            q.push_back(*seeds);
            q.push_back(0);
        }

        while (cur_depth < depth) {
            size = q.size();
            agg_mask = 0;
            // process each layer
            for (int i = 0; i < size; i++) {
                seed = q.front();
                q.pop_front();
                if (!CheckOnPath(seed, 0)) { // not on-path node
                    // evaluate prg and push directly
                    DLenPRG(seed, next_seeds);
                    q.push_back(next_seeds[0]);
                    q.push_back(next_seeds[1]);
                    
                    // in addition, we need aggregate all seeds according to each layer's bit
                    agg_mask ^= next_seeds[bits[cur_depth]];
                } else {
                    // 0 plays a placeholder of punctured value
                    if (bits[cur_depth]) {
                        q.push_back(0);
                        q.push_back(seeds[cur_depth]);
                    } else {
                        q.push_back(seeds[cur_depth]);
                        q.push_back(0);
                    }
                }
            }
            // correct the seed 
            path = ((path ^ 1) << 1) ^ bits[cur_depth];
            q[path] ^= agg_mask;
            cur_depth++;
        }

        for (int i = 0; i < length && i < q.size(); i++) {
            v[i] = q[i];
        }
    }


    void Expand(uint64_t length, uint64_t x, T *seeds, T *v) {
        int depth = int(log2(length)) + 1;
        // cout << "start expand" << v.size() << endl;
        if (role == Role::Sender) {
            SimpleExpand(0, depth, 0, *seeds, v);
        } else {
            PunctureExpand(depth, x, seeds, v);
        }
        // cout << "end expand" << endl;
    }

    void PrepareCorrelation(int cur_depth, int depth, T seed, T *str0, T *str1) {
        if (cur_depth == depth) {
            return;
        }

        T next_seeds[2];
        DLenPRG(seed, next_seeds);
        str0[cur_depth] ^= next_seeds[0];
        str1[cur_depth] ^= next_seeds[1];
        PrepareCorrelation(cur_depth + 1, depth, next_seeds[0], str0, str1);
        PrepareCorrelation(cur_depth + 1, depth, next_seeds[1], str0, str1);
    }

    void send_ot(const T* data0, const T* data1, int64_t length) {
        AlignedUnVector<std::array<block, 2>> data(length);
        sync_wait(sender->send(data, prg, chl));
        
        T *pad1 = new T[2*length];
        
        ////#pragma omp parallel for
        for (int64_t i = 0; i < length; ++i) {
            pad1[2*i] = *(T*)(data[i][0].data()) ^ data0[i];
            pad1[2*i+1] = *(T*)(data[i][1].data()) ^ data1[i];
        }
        
        sync_wait(sync(chl, role));
        coproto::span<T> a(pad1, 2*length);
        sync_wait(chl.send(a));
        
        delete[] pad1;
	}

	void recv_ot(T* datar, const BitVector &r, int64_t length) {
        vector<block> data(length);

        sync_wait(recver->receive(r, data, prg, chl));

		T *res = new T[2*length];
        sync_wait(sync(chl, role));
        
        coproto::span<T> a(res, 2*length);
        
        sync_wait(chl.recv(a));
        
        ////#pragma omp parallel for
        for(int64_t i = 0; i < length; i+=8) {
			for(int64_t j = 0; j < 8 and j < length-i; ++j) {
                assert((2*(i+j)+r[i+j]) < (length*2));
				datar[i+j] = res[2*(i+j)+r[i+j]] ^ *(T*)(data[i+j].data());
			}
		}
        delete[] res;
	}
};
