#include "secure-join/Defines.h"
#include "Level.h"

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#include <vector>
#include <functional>
#include <sstream>

namespace secJoin
{

	inline void share(oc::MatrixView<u8> d, u64 bits, BinMatrix& x0, BinMatrix& x1, PRNG& prng)
	{
		x0.resize(d.rows(), bits);
		x1.resize(d.rows(), bits);
		prng.get(x0.data(), x0.size());
		x0.trim();
		for (u64 i = 0; i < d.rows(); ++i)
		{
			for (u64 j = 0; j < x0.bytesPerEntry(); ++j)
			{
				x1(i, j) = d(i, j) ^ x0(i, j);
			}
		}
	}

	inline std::array<BinMatrix,2> share(BinMatrix d, PRNG& prng)
	{
		std::array<BinMatrix, 2> r;
		share(d.mData, d.bitsPerEntry(), r[0], r[1], prng);
		return r;
	}

	// plaintext version of the agg tree.
	struct PTree : public AggTreeParam
	{
		// upstream  (0) and downstream (1) levels.
		struct LevelPair
		{
			PLevel mUp, mDown;
			auto& operator[](int i)
			{
				return i ? mDown : mUp;
			}
		};

		std::vector<LevelPair> mLevels;

		std::vector<oc::BitVector> mPre, mSuf, mFull, mInput;

		oc::BitVector mCtrl;

		u64 bitCount = 0;

		std::function<std::string(const oc::BitVector&)> mFormatter = [](const oc::BitVector& bv) {
			std::stringstream ss;
			ss << bv;
			return ss.str();
		};

		void init(u64 n, u64 bitCount, PRNG& prng,
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op,
			std::function<std::string(const oc::BitVector&)> formatter = {});

		std::array<BinMatrix, 2> shareVals(PRNG& prng);


		std::array<BinMatrix, 2> shareBits(PRNG& prng);

		void loadLeaves(
			const std::vector<oc::BitVector>& s,
			const oc::BitVector& c);

		void upstream(
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op);


		void downstream(
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op);

		void leaves(
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op);

		void init(
			const std::vector<oc::BitVector>& s,
			const oc::BitVector& c,
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op,
			std::function<std::string(const oc::BitVector&)> formatter = {});

		std::string print(AggTreeType type = AggTreeType::Prefix);
	};

}