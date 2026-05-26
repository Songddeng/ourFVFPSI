#include "PlainAggTree.h"


namespace secJoin
{
    
		void PTree::init(u64 n, u64 bitCount, PRNG& prng,
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op,
			std::function<std::string(const oc::BitVector&)> formatter)
		{
			std::vector<oc::BitVector> s(n);

			oc::BitVector c(n);

			for (u64 i = 0; i < n; ++i)
			{
				s[i].resize(bitCount);

				u64 t = (i % bitCount);
				u64 v = (i / bitCount) + 1;
				for (u64 j = 0; j < std::min<u64>(bitCount, 64); ++j)
					s[i][(j + t) % bitCount] = *oc::BitIterator((u8*)&v, j);
				if (i)
					c[i] = prng.getBit();
			}

			init(s, c, op, std::move(formatter));
		}


		std::array<BinMatrix, 2> PTree::shareVals(PRNG& prng)
		{
			std::array<BinMatrix, 2> ret;
			ret[0].resize(mInput.size(), mInput[0].size());
			ret[1].resize(mInput.size(), mInput[0].size());

			oc::Matrix<u8> v(ret[0].numEntries(), ret[0].bytesPerEntry());
			for (u64 i = 0; i < v.rows(); ++i)
				osuCrypto::copyBytes(v[i], mInput[i]);

			share(v, ret[0].bitsPerEntry(), ret[0], ret[1], prng);

			return ret;
		}


		std::array<BinMatrix, 2> PTree::shareBits(PRNG& prng)
		{
			std::array<BinMatrix, 2> ret;
			ret[0].resize(mInput.size(), 1);
			ret[1].resize(mInput.size(), 1);

			oc::Matrix<u8> v(ret[0].numEntries(), 1);
			for (u64 i = 0; i < v.rows(); ++i)
				v(i) = mCtrl[i];

			share(v, ret[0].bitsPerEntry(), ret[0], ret[1], prng);

			return ret;
		}

		void PTree::loadLeaves(
			const std::vector<oc::BitVector>& s,
			const oc::BitVector& c)
		{

			mInput = s;
			mCtrl = c;

			bitCount = s[0].size();
			computeTreeSizes(s.size());

			mLevels.resize(mLevelSizes.size());
			for (u64 j = 0; j < 2; ++j)
			{
				for (u64 i = 0; i < mLevels.size(); ++i)
				{
					mLevels[i][j].resize(mLevelSizes[i]);
				}
			}

			for (u64 i = 0; i < mN; ++i)
			{
				auto q = i < mLevelSizes[0] ? 0 : 1;
				auto w = i < mLevelSizes[0] ? i : i - mR;
				if (mLevels.size() <= q)
					throw RTE_LOC;				
				if (mLevels[q].mUp.size() <= w)
					throw RTE_LOC;

				mLevels[q].mUp.mPreVal[w] = s[i];
				mLevels[q].mUp.mSufVal[w] = s[i];
				if (i)
					mLevels[q].mUp.mPreBit[w] = c[i];
				else
					mLevels[q].mUp.mPreBit[w] = 0;
				if (i != mN - 1)
					mLevels[q].mUp.mSufBit[w] = c[i + 1];
				else
					mLevels[q].mUp.mSufBit[w] = 0;

				//std::cout << s[i] << " " << mLevels[q].mUp.mPreBit[w] << " " << mLevels[q].mUp.mSufBit[w] << std::endl;
			}
			//std::cout << "\n";

			for (u64 i = mN; i < mN16; ++i)
			{
				auto q = i < mLevelSizes[0] ? 0 : 1;
				auto w = i < mLevelSizes[0] ? i : i - mR;

				if (mLevels.size() <= q)
					throw RTE_LOC;
				if (mLevels[q].mUp.size() <= w)
					throw RTE_LOC;

				mLevels[q].mUp.mPreVal[w].resize(bitCount);
				mLevels[q].mUp.mSufVal[w].resize(bitCount);
				mLevels[q].mUp.mPreBit[w] = 0;
				mLevels[q].mUp.mSufBit[w] = 0;
			}
		}
		void PTree::upstream(
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op)
		{
			for (u64 j = 1; j < mLevels.size(); ++j)
			{
				u64 end = mLevels[j - 1].mUp.size() / 2;
				auto& child = mLevels[j - 1].mUp;
				auto& parent = mLevels[j].mUp;

				for (u64 i = 0; i < end; ++i)
				{
					{
						auto v0 = child.mPreVal[2 * i];
						auto v1 = child.mPreVal[2 * i + 1];
						auto p0 = child.mPreBit[2 * i];
						auto p1 = child.mPreBit[2 * i + 1];

						parent.mPreVal[i] = p1 ? op(v0, v1) : v1;
						parent.mPreBit[i] = p1 * p0;

					}

					{
						auto v0 = child.mSufVal[2 * i];
						auto v1 = child.mSufVal[2 * i + 1];
						auto p0 = child.mSufBit[2 * i];
						auto p1 = child.mSufBit[2 * i + 1];

						parent.mSufVal[i] = p0 ? op(v0, v1) : v0;
						parent.mSufBit[i] = p1 * p0;

						//std::cout << parent.mSufVal[i] << " " << parent.mSufBit[i] << " = " << p0 <<" * " << p1 << std::endl;

					}
				}
				//std::cout << std::endl;
			}

		}


		void PTree::downstream(
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op)
		{
			assert(mLevels.back().mUp.size() == 1);
			mLevels.back().mDown = mLevels.back().mUp;

			for (u64 j = mLevels.size() - 1; j != 0; --j)
			{
				auto& parent = mLevels[j].mDown;
				auto& childDn = mLevels[j - 1].mDown;
				auto& childUp = mLevels[j - 1].mUp;
				u64 end = childDn.size() / 2;
				childDn.mPreBit = childUp.mPreBit;
				childDn.mSufBit = childUp.mSufBit;

				for (u64 i = 0; i < end; ++i)
				{
					{
						auto& v = parent.mPreVal[i];
						auto& v0 = childUp.mPreVal[i * 2];
						//auto& v1 = childUp.mPreVal[i * 2 + 1];
						auto& d0 = childDn.mPreVal[i * 2];
						auto& d1 = childDn.mPreVal[i * 2 + 1];
						auto p0 = childUp.mPreBit[i * 2];

						assert(v.size());
						assert(v0.size());
						//assert(v1.size());

						d1 = p0 ? op(v, v0) : v0;
						d0 = v;
					}
					{
						auto& v = parent.mSufVal[i];
						//auto& v0 = childUp.mSufVal[i * 2];
						auto& v1 = childUp.mSufVal[i * 2 + 1];
						auto& d0 = childDn.mSufVal[i * 2];
						auto& d1 = childDn.mSufVal[i * 2 + 1];
						auto p1 = childUp.mSufBit[i * 2 + 1];

						d0 = p1 ? op(v1, v) : v1;
						d1 = v;

						//std::cout << d0 << " " << " " << p1 << "\n" << d1 << std::endl;

					}
				}
				//std::cout << std::endl;
			}
		}

		void PTree::leaves(
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op)
		{
			mPre.resize(mN);
			mSuf.resize(mN);
			mFull.resize(mN);
			std::vector<oc::BitVector> expPre(mN), expSuf(mN);

			for (u64 i = 0; i < mN; ++i)
			{
				auto q = i < mLevelSizes[0] ? 0 : 1;
				auto w = i < mLevelSizes[0] ? i : i - mR;

				auto& ll = mLevels[q].mDown;

				expPre[i] = mCtrl[i] ? op(expPre[i - 1], mInput[i]) : mInput[i];


				auto ii = mN - 1 - i;
				u64 c = i ? mCtrl[ii + 1] : 0;
				expSuf[ii] = c ? op(mInput[ii], expSuf[ii + 1]) : mInput[ii];
				//u64 c = (ii != n - 1) ? mCtrl[ii+1] : 0;
				//expSuf[ii] = c ? op(mInput[ii], expSuf[ii + 1]) : mInput[ii];
				//std::cout << mInput[ii] << " " << c << " -> "<< expSuf[ii] << std::endl;

				mPre[i] = ll.mPreBit[w] ? op(ll.mPreVal[w], mInput[i]) : mInput[i];
				mSuf[i] = ll.mSufBit[w] ? op(mInput[i], ll.mSufVal[w]) : mInput[i];
				mFull[i] = ll.mPreBit[w] ? mPre[i] : mInput[i];
				mFull[i] = ll.mSufBit[w] ? op(mFull[i], ll.mSufVal[w]) : mFull[i];

				//std::cout << mInput[i] << " " << mCtrl[i] << " -> " << expPre[i] << " " << mPre[i] << std::endl;
			}

			//std::cout << "\n";
			//for (u64 i = 0; i < n; ++i)
			//{
			//	//u64 c = (i != n - 1) ? mCtrl[i + 1] : 0;
			//	//u64 c = mCtrl[i];
			//	//std::cout << mInput[i] << " " << c << " -> " << expSuf[i] << " " << mSuf[i] << "  " << (expSuf[i] ^ mSuf[i]) << std::endl;

			//}

			if (mPre != expPre)
				throw RTE_LOC;
			if (mSuf != expSuf)
				throw RTE_LOC;
		}

		void PTree::init(
			const std::vector<oc::BitVector>& s,
			const oc::BitVector& c,
			std::function<oc::BitVector(const oc::BitVector&, const oc::BitVector&)> op,
			std::function<std::string(const oc::BitVector&)> formatter)
		{

			if (formatter)
				mFormatter = std::move(formatter);

			loadLeaves(s, c);
			upstream(op);
			downstream(op);
			leaves(op);
		}


		std::string PTree::print(AggTreeType type)
		{
			std::stringstream ss;

			if (type == AggTreeType::Prefix)
			{

				for (u64 l = 0; l < mLevels.size(); ++l)
				{
					std::cout << "[ up lvl: " << l  << std::endl;
					for (u64 j = 0; j < mLevels[l].mUp.mPreVal.size(); ++j) {
						std::cout << l << "." << j << " (" << mFormatter(mLevels[l].mUp.mPreVal[j]) << ", " << mLevels[l].mUp.mPreBit[j] << ")";
						auto child = j * 2;
						if (l && mLevels[l - 1].mUp.mPreVal.size() > child)
						{

							std::cout << " = " << mLevels[l - 1].mUp.mPreBit[child + 1] << " ? op(" <<
								mFormatter(mLevels[l - 1].mUp.mPreVal[child]) << ", " <<
								mFormatter(mLevels[l - 1].mUp.mPreVal[child + 1]) << ") : " <<
								mFormatter(mLevels[l - 1].mUp.mPreVal[child + 1]);

							// parent.mPreVal[i] = p1 ? op(v0, v1) : v1;
							// parent.mPreBit[i] = p1 * p0;
						}
						std::cout << std::endl;
					}
					std::cout << "]" << std::endl;
				}


				for (u64 l = mLevels.size()-1; l < mLevels.size(); --l)
				{
					std::cout << "[ dwn lvl: " <<l << std::endl;
					for (u64 j = 0; j < mLevels[l].mDown.mPreVal.size(); ++j) {
						std::cout << l << "." << j << " (" << mFormatter(mLevels[l].mDown.mPreVal[j]) << ", " << mLevels[l].mDown.mPreBit[j] << ")";
						//auto child = j * 2;
						if (l != mLevels.size() -1)
						{
							auto parent = j / 2;
							auto sibling = j ^ 1;
							if (j & 1)
							{
								std::cout << " = " << mLevels[l].mDown.mPreBit[sibling] << " ? op(" <<
									mFormatter(mLevels[l + 1].mDown.mPreVal[parent]) << ", " <<
									mFormatter(mLevels[l].mDown.mPreVal[sibling]) << ") : " <<
									mFormatter(mLevels[l].mDown.mPreVal[sibling]);
							}
							else
							{
								std::cout << " = " << mFormatter(mLevels[l + 1].mDown.mPreVal[parent]);
							}
							//d1 = p0 ? op(v, v0) : v0;
							//d0 = v;
						}
						std::cout << std::endl;
					}
					std::cout << "]" << std::endl;
				}

			}
			else
			{
				throw RTE_LOC;
			}

			return ss.str();
		}
}