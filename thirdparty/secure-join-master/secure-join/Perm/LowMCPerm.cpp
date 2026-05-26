#include "LowMCPerm.h"



namespace secJoin
{

	const LowMC2<>& LowMCPermSender::mLowMc()
	{
		static const LowMC2<> m(false);
		return m;
	}

	const oc::BetaCircuit& LowMCPermSender::mLowMcCir() {
		static oc::BetaCircuit cir;
		if (cir.mGates.size() == 0)
		{

			LowMCPermSender::mLowMc().to_enc_circuit(cir);
			cir.levelByAndDepth();
		}
		return cir;
	}
	macoro::task<> LowMCPermSender::generate(Perm perm, PRNG& prng, coproto::Socket& chl, PermCorSender& dst)
	{
		if (perm.size() != mN)
			throw RTE_LOC;

		using lowBlock = LowMC2<>::block;
		auto blocksPerRow = oc::divCeil(mBytesPerRow, sizeof(lowBlock));
		oc::Matrix<lowBlock> delta(mN * blocksPerRow, 1, oc::AllocType::Uninitialized);
		dst.mPerm = std::move(perm);

		for (u64 i = 0, k = 0; i < mN; i++)
		{
			u64 srcIdx = dst.mPerm[i];
			for (u64 j = 0; j < blocksPerRow; j++, ++k)
			{
				// unchecked indexing ok due to the resize above.
				assert(blocksPerRow < (1ull << 32));
				delta.data()[k] = lowBlock(j + srcIdx << 32);
			}
		}
		// permutation indexes an messages
		mGmw.setInput(0, delta);

		// other party has the key.
		for (u8 i = 0; i < mLowMc().roundkeys.size(); i++)
			mGmw.setZeroInput(1 + i);

		co_await mGmw.run(chl);

		// get LowMC(perm[0]), ..., lowMC(perm[n-1])
		mGmw.getOutput(0, delta);
		auto d = span<lowBlock>(delta);
		dst.mDelta.resize(mN, divCeil(mBytesPerRow, sizeof(block)));
		for (u64 i = 0; i < mN; ++i)
		{
			osuCrypto::copyBytesMin(dst.mDelta[i], d.subspan(i * blocksPerRow, blocksPerRow));
		}
	}


	macoro::task<> LowMCPermReceiver::generate(PRNG& prng, coproto::Socket& chl, PermCorReceiver& dst)
	{

		if (mN == 0)
			throw std::runtime_error("AltModPermGenReceiver::init() must be called before setup. " LOCATION);

		using lowBlock = LowMC2<>::block;
		auto blocksPerRow = oc::divCeil(mBytesPerRow, sizeof(lowBlock));


		// B = (lowMC(k,pi(0)), ..., lowMC(k,pi(n-1)) )
		dst.mB.resize(mN, blocksPerRow);
		auto lowMc = LowMC2<>(0);
		auto lowKey = LowMC2<>::keyblock{};
		for(u64 i =0; i < lowKey.size(); ++i)
			lowKey[i] = prng.getBit();
		lowMc.set_key(lowKey);

		mGmw.setZeroInput(0);

		// Setting up the lowmc round keys
		oc::Matrix<lowBlock> roundkeysMatrix(mN * blocksPerRow, 1, oc::AllocType::Uninitialized);
		for (u64 i = 0; i < lowMc.roundkeys.size(); i++)
		{
			for (u64 j = 0; j < (mN * blocksPerRow); j++)
			{
				static_assert(sizeof(lowMc.roundkeys[i]) == sizeof(roundkeysMatrix(j)));
				std::copy(
					(u8*)&lowMc.roundkeys[i],
					(u8*)(&lowMc.roundkeys[i] + 1),
					(u8*)roundkeysMatrix.data(j));
			}
			mGmw.setInput(1 + i, roundkeysMatrix);
		}

		co_await mGmw.run(chl);


		// get LowMC(perm[0]), ..., lowMC(perm[n-1])
		oc::Matrix<lowBlock> B(mN * blocksPerRow, 1, oc::AllocType::Uninitialized);
		mGmw.getOutput(0, B);
		auto b = span<lowBlock>(B);
		dst.mB.resize(mN, divCeil(mBytesPerRow, sizeof(block)));
		dst.mA.resize(mN, divCeil(mBytesPerRow, sizeof(block)));
		for (u64 i = 0; i < mN; ++i)
		{
			osuCrypto::copyBytesMin(dst.mB[i], b.subspan(i * blocksPerRow, blocksPerRow));
		}

		std::vector<lowBlock> a(blocksPerRow);
		for (u64 i = 0; i < mN; i++)
		{
			for (u64 j = 0; j < blocksPerRow; j++)
			{
				// unchecked indexing ok due to the resize above.
				assert(blocksPerRow < (1ull << 32));
				a.data()[j] = lowBlock(j + i << 32);
				a.data()[j] = lowMc.encrypt(a.data()[j]);
			}

			osuCrypto::copyBytesMin(dst.mA[i], a);
		}

	}

}