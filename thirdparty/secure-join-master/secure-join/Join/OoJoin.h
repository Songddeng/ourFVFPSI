#pragma once

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Common/Timer.h>
#include "coproto/Socket/Socket.h"

#include "secure-join/Defines.h"
#include "secure-join/Join/Table.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/Perm/AltModPerm.h"
#include "secure-join/Join/JoinQuery.h"

namespace secJoin
{
    // one to one secure join.
    //
    // the right table will be mapped through the cuckoo hash table.
    class OoJoin :public oc::TimerAdapter
    {
    public:
        
        // we will pack columns into a matrix `data`.
        // offset tracks where each column starts in the data matrix.
        struct Offset
        {
            u64 mStart = 0, mSize = 0;
            std::string mName;
        };


        // statistical security parameter.
        u64 mStatSecParam = 40;

        // party index {0,1}
        u64 mPartyIdx = ~0ull;

        // the amount of data that will be permuted through the hash table.
        //u64 mDataBitsPerEntry = 0;

        // remove the dummy rows at the end of the protocol.
        bool mRemoveInactiveFlag = false;

        // the offset of the columns in the data matrix.
        std::vector<Offset> mOffsets;

        // the recver perm gen for either the first or second permutation
        AltModPermGenReceiver mPermGenRecv;

        // the sender perm gen for either the first or second permutation
        AltModPermGenSender mPermGenSend;

        AltModWPrfSender mSendHasher;

        AltModWPrfReceiver mRecvHasher;

        void init(
            JoinQuerySchema schema,
            CorGenerator& ole,
            PRNG& prng,
            bool remDummiesFlag = false);

        macoro::task<> join(
            JoinQuery query,
            Table& out,
            PRNG& prng,
            coproto::Socket& sock);


        std::array<std::vector<ColRef>, 2> groupSelectCols(JoinQuery& quert);
        //// join on leftJoinCol == rightJoinCol and select the select values.
        //SharedTable join(
        //    SharedTable:: leftJoinCol,
        //    ColRef rightJoinCol,
        //    std::vector<ColRef> selects);


        //SharedTable leftJoin(
        //    ColRef leftJoinCol,
        //    ColRef rightJoinCol,
        //    std::vector<ColRef> selects,
        //    std::string leftJoinColName)
        //{

        //    SelectQuery query;
        //    auto jc = query.joinOn(leftJoinCol, rightJoinCol);

        //    for (auto& s : selects)
        //    {
        //        if (&s.mCol == &leftJoinCol.mCol || &s.mCol == &rightJoinCol.mCol)
        //        {
        //            query.addOutput(s.mCol.mName, jc);
        //        }
        //        else
        //        {
        //            query.addOutput(s.mCol.mName, query.addInput(s));
        //        }
        //    }

        //    query.noReveal(leftJoinColName);

        //    return joinImpl(query);
        //}


        //SharedTable joinImpl(
        //    const SelectQuery& select
        //);

        // take all of the left table and any rows from the right table
        // where the rightJoinCol key is not in the left table. The returned
        // table will have the columns specified by leftSelects from the left table
        // and the rightSelects columns in the right table. Not that the data types
        // of leftSelects and rightSelects must match.
        SharedTable rightUnion(
            ColRef leftJoinCol,
            ColRef rightJoinCol,
            std::vector<ColRef> leftSelects,
            std::vector<ColRef> rightSelects);

        //void constructOutTable(
        //    std::vector<ColRef>& circuitInputLeftCols,
        //    std::vector<ColRef>& circuitInputRightCols,
        //    std::vector<ColRef>& circuitOutCols,
        //    std::vector<std::array<ColRef, 2>>& leftPassthroughCols,
        //    SharedTable& C,
        //    const JoinQuery& query);

        macoro::task<oc::AlignedUnVector<block>> hashKeys(JoinQuery& j);

        std::array<oc::Matrix<u8>, 3> mapRightTableToLeft(
            oc::Matrix<i64>& keys,
            span<ColRef> circuitInputCols,
            SharedTable& leftTable,
            SharedTable& rightTable);

        oc::Matrix<u8> cuckooHashRecv(span<ColRef> selects);
        void cuckooHashSend(span<ColRef> selects, oc::CuckooParam& cuckooParams);
        std::pair<Perm, BinMatrix> cuckooHash(span<ColRef> selects, span<block> keys);


        Perm selectCuckooPos(BinMatrix& table, BinMatrix& rightSelected, span<block> keys);
        //std::array<oc::Matrix<u8>, 3> selectCuckooPos(oc::MatrixView<u8> cuckooHashTable, u64 destRows);
        //void selectCuckooPos(u64 destRows, u64 srcRows, u64 bytes);

        
        macoro::task<> compare(
            BinMatrix& rightSelected,
            const JoinQuery& query,
            Table& out);

        TBinMatrix unionCompare(
            ColRef leftJoinCol,
            ColRef rightJoinCol,
            span<oc::Matrix<u8>> leftInData);

        oc::Matrix<i64> computeKeys(span<ColRef> tables, span<u64> reveals);

        BinMatrix loadTable(span<ColRef> selects);

        //BetaCircuit getQueryCircuit(
        //    span<SharedColumn*> leftCircuitInput,
        //    span<SharedColumn*> rightCircuitInput,
        //    span<SharedColumn*> circuitOutput,
        //    const SelectQuery& query);

        //BetaCircuit getBasicCompareCircuit(
        //    ColRef leftJoinCol,
        //    span<ColRef> cols);

        //BetaCircuit mLowMCCir;




        //void p0CheckSelect(MatrixView<u8> cuckoo, span<Matrix<u8>> a2);
        //void p1CheckSelect(Matrix<u8> cuckoo, span<Matrix<u8>> a2, aby3::i64Matrix& keys);
    };

}