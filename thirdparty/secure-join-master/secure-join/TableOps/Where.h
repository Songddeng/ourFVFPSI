#pragma once
#include "secure-join/Util/ArrGate.h"
#include "secure-join/Util/Matrix.h"
#include "secure-join/GMW/Gmw.h"
#include "secure-join/Defines.h"
#include "secure-join/Join/Table.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Circuit/Gate.h"
#include "cryptoTools/Common/BitVector.h"
#include "secure-join/Defines.h"
#include "secure-join/Perm/ComposedPerm.h"
#include "secure-join/Util/Util.h"
#include "secure-join/Join/OmJoin.h"
#include "Extract.h"

namespace secJoin
{

    struct Where
    {

        bool mInsecureMockSubroutines = false;
        bool mInsecurePrint = false;

		// the number of rows in the input table.
        u64 mRows = 0;

		// the columns of the input table.
		std::vector<ColumnInfo> mColumns;

		// the indices of the columns that will be used as inputs to the where clause.
		std::vector<u64> mWhereInputs;
		
        // the circuit that will be evaluated.
        oc::BetaCircuit mWhereClauseCir;

		// the gmw protocol to be evaluated.
        Gmw mGmw;

		// the remove inactive protocol.
       std::optional<Extract> mRemoveInactive;

        // initialize the where protocol.
		// `rows` is the number of rows in the input table.
		// `columns` the columns of the input table.
		// `whereInputs` is the indices of the columns that will be used as inputs to the where clause.
		// `whereClause` is the circuit that will be evaluated. It should have the same number 
        // of inputs as the size of the `whereInputs` vector. It should output a single bit which
		// is true if the row should be included in the output.
		// `ole` is the source of the correlated randomness.
		// `removeInactive` should be set to true if inactive rows should be removed from the output.
        void init(
            u64 rows,
            span<ColumnInfo> columns,
			span<u64> whereInputs,
            oc::BetaCircuit& whereClause,
            CorGenerator& ole,
            bool extractActive = false);


		// run the where protocol.
		// `input` is the input table. Can be the same as `output`.
		// `output` is the output table.
		// `sock` is the communication channel.
		// `prng` is the source of randomness.
        macoro::task<> where(
            const Table& input,
            Table& output,
            coproto::Socket& sock,
            PRNG& prng);


        // a helper function. 
	    // given cir, we add an additional input which is the isActive flag.
	    // the final output is the output of cir & isActive.
        static oc::BetaCircuit makeWhereClause(const oc::BetaCircuit& cir);
            

        //void genWhBundle(
        //    const std::vector<std::string>& literals, 
        //    const std::vector<std::string>& literalsType, 
        //    const u64 totalCol, SharedTable& st, 
        //    const std::unordered_map<u64, u64>& map);

        //u64 getInputColSize(
        //    SharedTable& st, 
        //    u64 gateInputIndex,
        //    u64 totalCol,
        //    const std::unordered_map<u64, u64>& map);
        //
        //void addToGmwInput(
        //    SharedTable& st, 
        //    u64 gateInputIndex,
        //    const std::unordered_map<u64, u64>& map, 
        //    WhType type);

        //oc::BetaCircuit updateActiveFlagCir(
        //    const u64 aSize, 
        //    const u64 bSize, 
        //    const u64 cSize);
        //    
        //macoro::task<> updateActiveFlag(
        //    std::vector<u8>& actFlag,
        //    BinMatrix& choice,
        //    coproto::Socket& sock);

        //void addInputBundle(
        //    oc::BetaCircuit& cd, 
        //    SharedTable& st,
        //    const u64 gateInputIndex, 
        //    const std::unordered_map<u64, u64>& map);

        ////u64 getMapVal(
        ////    const std::unordered_map<u64, u64>& map,
        ////    u64 tag);

        //void ArrTypeLessThanCir(
        //    const u64 inIndex1, 
        //    const u64 inIndex2, 
        //    oc::BetaCircuit& cd, 
        //    BetaBundle &c, 
        //    const bool lastOp);

        //void ArrTypeAddCir(
        //    const u64 inIndex1, 
        //    const u64 inIndex2, 
        //    oc::BetaCircuit& cd, 
        //    BetaBundle &c, 
        //    const bool lastOp);

        //void ArrTypeEqualCir(
        //    const u64 inIndex1, 
        //    const u64 inIndex2, 
        //    oc::BetaCircuit& cd, 
        //    BetaBundle &c, 
        //    const bool lastOp);

        //void ArrTypeEqualInputs(
        //    const u64 inIndex1, 
        //    const u64 inIndex2, 
        //    SharedTable& st,
        //    oc::BetaCircuit& cd, 
        //    const std::unordered_map<u64, u64>& map);
        //
        //void signExtend(
        //    const u64 smallerSizeIndex, 
        //    const u64 biggerSize,
        //    const u64 biggerSizeIndex,
        //    SharedTable& st, 
        //    oc::BetaCircuit& cd,
        //    const std::unordered_map<u64, u64>& map);

        //macoro::task<> getOutput(
        //    Table& in, 
        //    Table& out, 
        //    coproto::Socket& sock, 
        //    oc::PRNG& prng, 
        //    bool securePerm, 
        //    Perm& randPerm);


        //void signExtend(BitVector& aa, const u64 size, const WhType type);
        //void signExtend(BinMatrix& in, const u64 size, const ColumnType type);
        //void signExtend(BetaBundle& aa, const u64 size, const WhType type);
        //void extendBetaBundle(BetaBundle& aa, const u64 size);
        //void extendBitVector(BitVector& aa, const u8 bit, const u64 size);
    };



}


