#pragma once

#include "secure-join/Prf/LowMC.h"

#include "coproto/Common/Defines.h"
#include "coproto/Common/span.h"
#include "Permutation.h"
#include "secure-join/GMW/Gmw.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include <bitset>
#include "cryptoTools/Common/Matrix.h"
#include "coproto/coproto.h"
#include <numeric>
#include "secure-join/Perm/PermCorrelation.h"

namespace secJoin
{

	template<int n>
	inline std::string hex(std::bitset<n> b)
	{
		auto bb = *(std::array<u8, sizeof(b)>*) & b;
		std::stringstream ss;
		for (u64 i = 0; i < bb.size(); ++i)
			ss << std::hex << std::setw(2) << std::setfill('0') << int(bb[i]);
		return ss.str();
	}

	class LowMCPermSender
	{
	public:
		static const LowMC2<>& mLowMc();
		static const oc::BetaCircuit& mLowMcCir();

		Gmw mGmw;

		// the size of the permutation to be generated.
		u64 mN = 0;

		// the number of bytes per element to be generated.
		u64 mBytesPerRow = 0;

		// initialize this sender to have a permutation of size n, where 
		// bytesPerRow bytes can be permuted per position. keyGen can be 
		// set if the caller wants to explicitly ask to perform AltMod keygen or not.
		void init(
			u64 n,
			u64 bytesPerRow,
			CorGenerator& cor,
			span<std::array<block, 2>> atlModKeys = {})
		{
			mN = n;
			mBytesPerRow = bytesPerRow;
			u64 blocks = n * divCeil(bytesPerRow, sizeof(LowMC2<>::block));
			mGmw.init(blocks, mLowMcCir(), cor);
		}

		// this will request CorGen to start our preprocessing
		void preprocess()
		{
			mGmw.preprocess();
		}

		// Generate the correlated randomness for the permutation pi. pi will either
		// be mPi if it is already known or it will be mPrePerm.
		macoro::task<> generate(
			Perm perm,
			PRNG& prng,
			coproto::Socket& chl,
			PermCorSender& dst);

		void clear() {
			mGmw.clear();
			mN = 0;
			mBytesPerRow = 0;
		}
	};

	class LowMCPermReceiver
	{
	public:

		Gmw mGmw;

		// the size of the permutation to be generated.
		u64 mN = 0;

		// the number of bytes per element to be generated.
		u64 mBytesPerRow = 0;

		// initialize this sender to have a permutation of size n, where 
		// bytesPerRow bytes can be permuted per position. keyGen can be 
		// set if the caller wants to explicitly ask to perform AltMod keygen or not.
		void init(
			u64 n,
			u64 bytesPerRow,
			CorGenerator& cor,
			span<std::array<block, 2>> atlModKeys = {})
		{
			mN = n;
			mBytesPerRow = bytesPerRow;
			u64 blocks = n * divCeil(bytesPerRow, sizeof(LowMC2<>::block));
			mGmw.init(blocks, LowMCPermSender::mLowMcCir(), cor);
		}

		// this will request CorGen to start our preprocessing
		void preprocess()
		{
			mGmw.preprocess();
		}

		// Generate the correlated randomness for the permutation pi.
		macoro::task<> generate(
			PRNG& prng,
			coproto::Socket& chl,
			PermCorReceiver& dst);

		void clear() {
			mGmw.clear();
			mN = 0;
			mBytesPerRow = 0;
		}
	};

}