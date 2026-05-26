#pragma once

#include "secure-join/Defines.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
namespace secJoin
{

	// this is a partially implemented version of the Chase et al permutation protocol.
	// Only used for benchmarking.
	struct PprfPermGenSender
	{
		oc::RegularPprfSender<oc::block> mSender;
		oc::AlignedUnVector<oc::block> mVal, mOutput;

		void init(u64 n, u64 t)
		{
			mSender.configure(t, n);
			mOutput.resize(n * t);
		}

		macoro::task<> gen(coproto::Socket& s, oc::PRNG& prng)
		{
			auto base = std::vector<std::array<block, 2>>(mSender.baseOtCount());
			auto ot = oc::SoftSpokenShOtSender<>{};

			co_await ot.send(base, prng, s);
			mSender.setBase(base);
			co_await mSender.expand(s, mVal, prng.get(), mOutput, oc::PprfOutputFormat::ByTreeIndex, false, 1);
		}
	};

	// this is a partially implemented version of the Chase et al permutation protocol.
	// Only used for benchmarking.
	struct PprfPermGenReceiver
	{
		oc::RegularPprfReceiver<oc::block> mRecver;
		oc::AlignedUnVector<oc::block> mVal, mOutput;
		u64 mBaseCount = 0;

		void init(u64 n, u64 t)
		{
			mRecver.configure(t, n);
			mOutput.resize(n * t);
		}

		macoro::task<> gen(coproto::Socket& s, PRNG& prng)
		{
			auto base = std::vector<block>(mRecver.baseOtCount());
			auto bits = oc::BitVector(mRecver.baseOtCount());
			auto ot = oc::SoftSpokenShOtReceiver<>{};

			co_await ot.receive(bits, base, prng, s);
			mRecver.setChoiceBits(bits);
			mRecver.setBase(base);
			co_await mRecver.expand(s, mOutput, oc::PprfOutputFormat::ByTreeIndex, false, 1);
		}
	};
}