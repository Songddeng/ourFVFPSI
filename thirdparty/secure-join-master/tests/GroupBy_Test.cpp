#include "GroupBy_Test.h"
#include "cryptoTools/Common/TestCollection.h"

#include "secure-join/TableOps/GroupBy.h"
#include "secure-join/Util/Util.h"

using namespace secJoin;

void evalGroupBy
    ( Table& T,
    const u64 grpByColIdx,
    const std::vector<u64> avgColIdxs,
    const bool printSteps,
    const bool mock)
{
    auto sock = coproto::LocalAsyncSocket::makePair();

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);

    std::array<Table, 2> Ts;
    T.share(Ts, prng0);

    u64 rows = T.rows();

    Ts[0].mIsActive.resize(rows);
    Ts[1].mIsActive.resize(rows);
    for (u64 i = 0; i < rows; i++)
    {
        Ts[0].mIsActive[i] = 1;
        Ts[1].mIsActive[i] = 0;
    }

    std::vector<ColRef> plnAvgColRef, shAvgColRef0, shAvgColRef1;

    for(u64 i = 0; i < avgColIdxs.size(); i++)
    {
        plnAvgColRef.emplace_back(T[avgColIdxs[i]]);
        shAvgColRef0.emplace_back(Ts[0][avgColIdxs[i]]);
        shAvgColRef1.emplace_back(Ts[1][avgColIdxs[i]]);
    }

    CorGenerator ole0, ole1;

    for (auto remDummies : { false, true })
    {
        ole0.init(sock[0].fork(), prng0, 0, 1, 1 << 16, mock);
        ole1.init(sock[1].fork(), prng1, 1, 1, 1 << 16, mock);

        GroupBy avg0, avg1;

        avg0.mInsecurePrint = printSteps;
        avg1.mInsecurePrint = printSteps;

        avg0.mInsecureMockSubroutines = mock;
        avg1.mInsecureMockSubroutines = mock;

        avg0.init(Ts[0][grpByColIdx], shAvgColRef0, ole0, remDummies);
        avg1.init(Ts[1][grpByColIdx], shAvgColRef1, ole1, remDummies);

        //avg0.mRemoveInactive.mCachePerm = remDummies;
        //avg1.mRemoveInactive.mCachePerm = remDummies;

        Table out[2];
        auto r = macoro::sync_wait(macoro::when_all_ready(
               ole0.start(), ole1.start(),
               avg0.groupBy(Ts[0][grpByColIdx], shAvgColRef0, out[0], prng0, sock[0]),
               avg1.groupBy(Ts[1][grpByColIdx], shAvgColRef1, out[1], prng1, sock[1])
           )
        );

        std::get<0>(r).result();
        std::get<1>(r).result();
        std::get<2>(r).result();
        std::get<3>(r).result();

        Table res;

        res = reveal(out[0], out[1], false);

        T.average(T[0], { T[1], T[2] });

        if (res != T)
        {
            std::cout << "remove dummies flag = " << remDummies << std::endl;
            std::cout << "exp \n" << T << std::endl;
            std::cout << "act \n" << res << std::endl;
            std::cout << "ful \n" << reveal(out[0], out[1], false) << std::endl;
            throw RTE_LOC;
        }

        if(printSteps)
            std::cout << "Rem Dummies Flag = " << remDummies << " Complete" << std::endl;
    }

}


void GroupBy_concatColumns_Test()
{
    throw oc::UnitTestSkipped("not functional");

    u64 n0 = 2345;
    Table t0;
    t0.mColumns.emplace_back("c0", ColumnType::Int, 11);
    t0.mColumns.emplace_back("c1", ColumnType::Int, 31);
    t0.mColumns.emplace_back("c2", ColumnType::Int, 5);
    t0.mIsActive.resize(n0);
    t0.resize(n0);

    auto sock = coproto::LocalAsyncSocket::makePair();

    GroupBy avg;

    PRNG prng(oc::ZeroBlock);
    for (u64 i = 0; i < t0.mColumns.size(); ++i)
    {
        prng.get(t0[i].mCol.mData.data(), t0[i].mCol.mData.size());
        t0[i].mCol.mData.trim();
    }
    
    for (u64 i = 0; i < t0.rows(); ++i)
        t0.mIsActive[i] = 1;

    ColRef groupByCol = t0[0];
    std::vector<ColRef> avgCols = { t0[1], t0[2] };
    BinMatrix compressKeys, y;
    
    CorGenerator ole;
    ole.init(coproto::Socket{}, prng, 1, 1, 1<<16, true);

    BinMatrix ones(n0, sizeof(oc::u64) * 8);
    for (oc::u64 i = 0; i < n0; i++)
        ones(i, 0) = 1;

    // Validation logic
    for (u64 i = 0; i < n0; ++i)
    {
        auto iter = oc::BitIterator(y.mData[i].data());
        
        // Checking the GroupBy Columns
        for (u64 j = 0; j < avgCols.size(); ++j)
        {
            auto expIter = oc::BitIterator(avgCols[j].mCol.mData.data(i));
            for (u64 k = 0; k < avgCols[j].mCol.getBitCount(); ++k)
            {
                u8 exp = *expIter++;
                u8 act = *iter++;
                if (exp != act)
                    throw RTE_LOC;
            }

            auto rem = avgCols[j].mCol.getBitCount() % 8;
            if (rem)
                iter = iter + (8 - rem);
        }

        // Checking the ones column
        auto expIter = oc::BitIterator(ones.data(i));

        for (u64 k = 0; k < ones.mBitCount; ++k)
        {
            u8 exp = *expIter++;
            u8 act = *iter++;
            if (exp != act)
                throw RTE_LOC;
        }
        auto rem = ones.bitsPerEntry() % 8;
        if (rem)
            iter = iter + (8 - rem);

        // Checking the groupby column
        expIter = oc::BitIterator(groupByCol.mCol.mData.data(i));

        for (u64 k = 0; k < groupByCol.mCol.mBitCount; ++k)
        {
            u8 exp = *expIter++;
            u8 act = *iter++;
            if (exp != act)
                throw RTE_LOC;
        }
        rem = groupByCol.mCol.getBitCount() % 8;
        if (rem)
            iter = iter + (8 - rem);

        // Checking the compressKeys
        expIter = oc::BitIterator(compressKeys.data(i));

        for (u64 k = 0; k < compressKeys.bitsPerEntry(); ++k)
        {
            u8 exp = *expIter++;
            u8 act = *iter++;
            if (exp != act)
                throw RTE_LOC;
        }
        rem = compressKeys.bitsPerEntry() % 8;
        if (rem)
            iter = iter + (8 - rem);

        // Checking the active Flag
        u8 exp = t0.mIsActive[i];
        u8 act = *iter++;
        if (exp != act)
            throw RTE_LOC;

    }
}



void GroupBy_getControlBits_Test(const oc::CLP& cmd)
{
    throw oc::UnitTestSkipped("not functional");
    u64 n = 342;
    u64 keyBitCount = 21;
    auto mock = cmd.getOr("mock", 1);

    auto sock = coproto::LocalAsyncSocket::makePair();

    BinMatrix keys(n, keyBitCount), kk[2], cc[2];
    PRNG prng(oc::ZeroBlock);
    prng.get(keys.data(), keys.size());

    std::vector<u8> exp(n);
    for (u64 i = 1; i < n; ++i)
    {
        exp[i] = prng.getBit();
        if (exp[i])
        {
            osuCrypto::copyBytes(keys[i], keys[i - 1]);
            // m emcpy(keys.data(i), keys.data(i - 1), keys.cols());
        }
    }

    share(keys, kk[0], kk[1], prng);

    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng, 0, 1, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng, 1, 1, 1 << 16, mock);

    GroupBy avg[2];

    avg[0].mControlBitGmw.init(n, OmJoin::getControlBitsCircuit(keyBitCount), ole0);
    avg[1].mControlBitGmw.init(n, OmJoin::getControlBitsCircuit(keyBitCount), ole1);

    auto r = macoro::sync_wait(macoro::when_all_ready(
        ole0.start(),
        ole1.start(),
        avg[0].getControlBits(kk[0], sock[0], cc[0]),
        avg[1].getControlBits(kk[1], sock[1], cc[1])));

    std::get<0>(r).result();
    std::get<1>(r).result();

    auto c = reveal(cc[0], cc[1]);

    if (c.mData(0))
        throw RTE_LOC;
    for (u64 i = 1; i < n; ++i)
    {
        auto act = c(i);
        if (exp[i] != act)
            throw RTE_LOC;
    }
}

void GroupBy_avg_Test(const oc::CLP& cmd)
{
    throw oc::UnitTestSkipped("not functional");
    u64 nT = cmd.getOr("nT", 10);
    Table T;

    bool printSteps = cmd.isSet("print");
    bool mock = cmd.getOr("mock", 1);

    T.init(nT, { {
        {"L1", ColumnType::Int, 12},
        {"L2", ColumnType::Int, 16},
        {"L3", ColumnType::Int, 16}
    } });

    for (u64 i = 0; i < nT; ++i)
    {
        T.mColumns[0].mData.mData(i, 0) = i % 5;
        T.mColumns[1].mData.mData(i, 0) = i % 4;
        T.mColumns[1].mData.mData(i, 1) = i % 4;
        T.mColumns[2].mData.mData(i, 0) = i % 4;
        T.mColumns[2].mData.mData(i, 1) = i % 4;
    }

    GroupBy avg1, avg2;

    avg1.mInsecurePrint = printSteps;
    avg2.mInsecurePrint = printSteps;

    avg1.mInsecureMockSubroutines = mock;
    avg2.mInsecureMockSubroutines = mock;

    auto sock = coproto::LocalAsyncSocket::makePair();

    PRNG prng0(oc::ZeroBlock);
    PRNG prng1(oc::OneBlock);

    std::array<Table, 2> Ts;
    T.share(Ts, prng0);

    Ts[0].mIsActive.resize(nT);
    Ts[1].mIsActive.resize(nT);
    for (u64 i = 0; i < nT; i++)
    {
        Ts[0].mIsActive[i] = 1;
        Ts[1].mIsActive[i] = 0;
    }

    T.average(T[0], { T[1], T[2] });

    CorGenerator ole0, ole1;
    ole0.init(sock[0].fork(), prng0, 0, 1, 1 << 16, mock);
    ole1.init(sock[1].fork(), prng1, 1, 1, 1 << 16, mock);

    for (auto remDummies : { false, true })
    {
        Perm p0(T.rows(), prng0);
        Perm p1(T.rows(), prng1);
        Perm pi = p1.compose(p0);

        Table out[2];
        auto r = macoro::sync_wait(macoro::when_all_ready(
            avg1.groupBy(Ts[0][0], { Ts[0][1], Ts[0][2] }, out[0], prng0, sock[0]),
            avg2.groupBy(Ts[1][0], { Ts[1][1], Ts[1][2] }, out[1], prng1, sock[1])
        ));
        std::get<0>(r).result();
        std::get<1>(r).result();

        Table res;

        res = reveal(out[0], out[1]);

        if (remDummies)
        {
            throw RTE_LOC;
            //Table tmp = applyPerm(exp, pi);
            //std::swap(exp, tmp);
        }

        if (res != T)
        {
            std::cout << "remove dummies flag = " << remDummies << std::endl;
            std::cout << "exp \n" << T << std::endl;
            std::cout << "act \n" << res << std::endl;
            std::cout << "ful \n" << reveal(out[0], out[1], false) << std::endl;
            throw RTE_LOC;
        }
    }

}

void GroupBy_avg_BigKey_Test(const oc::CLP& cmd)
{
    throw oc::UnitTestSkipped("not functional");
    //u64 nT = cmd.getOr("nT", 10);
    //Table T;

    //bool printSteps = cmd.isSet("print");
    //bool mock = cmd.getOr("mock", 1);

    //std::vector<oc::u64> joinCols, selectCols, groupByCols, avgCols;
    //u64 startIndex = 0;
    //parseColsArray(joinCols, selectCols, groupByCols, avgCols, opInfo, startIndex, printSteps);
    //updateSelectCols(selectCols, groupByCols, avgCols, printSteps);

    //oc::u64 lRowCount = 0, rRowCount = 0, lColCount = 0, rColCount = 0;
    //bool isBin;

    //std::vector<ColumnInfo> lColInfo, rColInfo;
    //getFileInfo(primaryMetaDataPath, lColInfo, lRowCount, lColCount, isBin);
    //getFileInfo(clientMetaDataPath, rColInfo, rRowCount, rColCount, isBin);

    //Table L, R;

    //L.init(lRowCount, lColInfo);
    //R.init(rRowCount, rColInfo);

    //populateTable(L, primaryCsvPath, lRowCount, isBin);
    //populateTable(R, secondatyCsvPath, rRowCount, isBin);

    //// Get Select Col Refs
    //std::vector<secJoin::ColRef> selectColRefs = getSelectColRef(selectCols, L, R);

    //// if (printSteps)
    //// {
    ////     std::cout << "L\n" << L << std::endl;
    ////     std::cout << "R\n" << R << std::endl;
    //// }

    //PRNG prng(oc::ZeroBlock);
    //std::array<Table, 2> Ls, Rs;
    //share(L, Ls, prng);
    //share(R, Rs, prng);

    //CorGenerator ole0, ole1;
    //PRNG prng0(oc::ZeroBlock);
    //PRNG prng1(oc::OneBlock);
    //auto sock = coproto::LocalAsyncSocket::makePair();
    //ole0.init(sock[0].fork(), prng0, 0,1,  1 << 16, mock);
    //ole1.init(sock[1].fork(), prng1, 1,1,  1 << 16, mock);

    //for (u64 i = 0; i < nT; ++i)
    //{
    //    T.mColumns[0].mData.mData(i, 0) = i % 5;
    //    T.mColumns[1].mData.mData(i, 0) = i % 4;
    //    T.mColumns[1].mData.mData(i, 1) = i % 4;
    //    T.mColumns[2].mData.mData(i, 0) = i % 4;
    //    T.mColumns[2].mData.mData(i, 1) = i % 4;
    //}

    //evalGroupBy( T, 0, {1 ,2} , printSteps, mock);

}
