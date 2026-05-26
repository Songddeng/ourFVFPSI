#pragma once
#include "cryptoTools/Circuit/BetaCircuit.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iomanip>
#include "PerfectShuffle.h"
#include <functional>
#include "Level.h"
#include "libOTe/Tools/Tools.h"
#include "coproto/Socket/Socket.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/GMW/Gmw.h"

//#include "reveal.h"

namespace secJoin
{
	// This class implements a prefix, suffix or full aggregation tree, 
	// elements an input vector based on a bit vector.
	// Given an input vector x=(x1,x2,...,xn) and bit vector preBit=(0,sufBit,...,bn),
	// 
	// A 'block' is defined as {i,i+1...,j} where 𝑏_𝑖,𝑏_{𝑖+1},…, 𝑏_𝑗=(0,1,1,…,1)
	// and 𝑏_{𝑗+1}=0.
	// 
	// The apply(x,preBit,...) function will output the vector y=(y1,y2,...,yn)
	// 
	// prefix: for each block {i,...,j}
	//		𝑦_𝑖  = 𝑣_𝑖 
	//      𝑦_𝑖′ = 𝑦_𝑖′ ⊕ 𝑣_{𝑖′−1}      :𝑖′∈{𝑖+1,…,𝑗}
	//
	// suffix: for each block {i,...,j}
	//     𝑦_𝑗  = 𝑣_𝑗
	//     𝑦_𝑗′ = 𝑣_𝑗′ ⊕ 𝑦_{𝑗′+1}      :𝑗^′∈{𝑗−1,…,𝑖}
	// 
	// Full: for each block {i,...,j}
	//	   𝑦_𝑖′ = 𝑣_𝑖 ⊕ … ⊕ 𝑣_𝑗      :𝑖^′∈{𝑖,…,𝑗}
	// 
	// 
	class AggTree : public AggTreeParam
	{
	public:
		using Type = AggTreeType;

		// The + function. Takes as input two values
		// and output the addition of them.
		using Operator = std::function<
			void(
				oc::BetaCircuit& c,
				const oc::BetaBundle& left,
				const oc::BetaBundle& right,
				oc::BetaBundle& out)>;

		using Level = AggTreeLevel;
		using SplitLevel = AggTreeSplitLevel;

		// the circuits that are used for the various phases.
		oc::BetaCircuit mUpCir, mDownCir, mLeafCir;

		// The GMW subprotocols used for the upstream and downstream levels, 
		// one for each lvl of the tree.
		std::vector<Gmw> mUpGmw, mDownGmw;

		// the GMW subprotocol used to update the leaf values at the end.
		Gmw mLeafGmw;

		// the type of aggregation to be performed.
		Type mType = Type::Prefix;

		// the number of bits each entry will have. Not counting the control bit.
		u64 mBitsPerEntry = 0;

		// initialize an agg tree with n leaves, each with bitsPerEntry bits.
		// The agggregation of `type` is performed and aggraegated using `op`.
		// the ole correlations used to evalute the circuit are obtained from
		// `gen`.
		void init(
			u64 n,
			u64 bitsPerEntry,
			Type type,
			const Operator& op,
			CorGenerator& gen);

		// perform the actual protocol. `src` are the input data, 
		// `controlBits` are the bits that determine the regions.
		// communication is performed via `comm`. The output is
		// written to `dst`.
		macoro::task<> apply(
			const BinMatrix& src,
			const BinMatrix& controlBits,
			coproto::Socket& comm,
			PRNG& prng,
			BinMatrix& dst);

		// take the rows
		//  in[srcRowStartIdx]
		//  ...
		//  in[srcRowStartIdx + numRows]
		//
		// and store the bit-transpose in dest. So each 
		// row j of dest will have the form 
		// 
		// dest[j] =  in(srcRowStartIdx,j), in(srcRowStartIdx+1,j),...,in(srcRowStartIdx+numRows,j)
		// 
		//static void toPackedBin(const BinMatrix& in, TBinMatrix& dest,
		//    u64 srcRowStartIdx,
		//    u64 numRows);

		/* This circuit outputs pre,suf,preVal where

					 |  pre  = prep1 ? pre_0 + pre_1 : pre_1,
					 |  suf  = sufp0 ? suf_0 + suf_1 : suf_0
					 *  prep = prep0 * prep1
					 *  sufp = sufp0 * sufp1
					/ \
				   /   \
				  /     \
			  pre_0,    pre_1
			  suf_0,    suf_1
			  prep_0,   prep_1
			  sufp_0,   sufp_1
		*/
		static oc::BetaCircuit upstreamCir(
			u64 bitsPerEntry,
			Type type,
			const Operator& add);

		// Perform the upstream computation. Here we want to compute several
		// values for each node of the tree. Each node will hold 
		// 
		//  push up value val, left child value v0, a product preVal
		//
		// The value will be val=v_{1+p1} where v0,v1 are the left and right child
		// values. The product preVal will be preVal=p0*p1 where p0,p1 are the left and 
		// right child product values.  
		//
		// At the leaf level val will be the corresponding input value. preVal will be
		// the control bit to the leaf'sufVal right. I.e., for leaf i, preVal = controlBit[i-1] 
		// and preVal will be zero for the left most leaf (i.e. i=0).
		//
		// For each level of the tree, starting at the preSuf, we compute the 
		// parent values as described.
		macoro::task<> upstream(
			const BinMatrix& src,
			const BinMatrix& controlBits,
			coproto::Socket& comm,
			PRNG& prng,
			Level& root,
			span<SplitLevel> levels);

		/* this circuit pushes values down the tree.

					   |  pre, suf, _
					   |
					   *
					  / \
					 /   \
					/     \
			  pre_0,      pre_1
			  suf_0,      suf_1
			  p_0,        p_1

		   These values are updated as
			 pre_1 := p_0 ? pre_0 + pre : pre_0
			 pre_0 := pre
			 suf_0 := suf_1 + suf : suf_1
			 suf_1 := suf

		   circuit inputs are
		   - left Val
		   - left bit
		   - parent val

		   outputs are:
		   - left val
		   - right val

		   Prefix input outputs go first and then suffix. So the i/o above is repeated twice.

		*/
		static oc::BetaCircuit downstreamCir(u64 bitsPerEntry, const Operator& op, Type type);


		// apply the downstream circuit to each level of the tree.
		macoro::task<> downstream(
			const BinMatrix& src,
			Level& root,
			span<SplitLevel> levels,
			SplitLevel& preSuf,
			coproto::Socket& comm,
			PRNG& prng,
			std::vector<SplitLevel>* debugLevels = nullptr);

		oc::BetaCircuit leafCircuit(u64 bitsPerEntry, const Operator& op, Type type);

		//	// apply the downstream circuit to each level of the tree.
		macoro::task<> computeLeaf(
			SplitLevel& leaves,
			SplitLevel& preSuf,
			BinMatrix& dst,
			PRNG& prng,
			coproto::Socket& comm);


	};
}