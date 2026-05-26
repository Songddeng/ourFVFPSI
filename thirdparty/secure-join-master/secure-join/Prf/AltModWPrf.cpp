

#include "AltModWPrf.h"
#include "secure-join/AggTree/PerfectShuffle.h"
#include "mod3.h"
#define AltMod_NEW
#include <ranges>
#include "macoro/async_scope.h"

namespace secJoin
{



	void AltModWPrfSender::setKeyOts(
		AltModPrf::KeyType k,
		span<const block> ots,
		span<const std::array<block, 2>> sendOts)
	{
		mKeyMultRecver.setKeyOts(k, ots);

		if (mKeyMode == AltModPrfKeyMode::Shared &&
			mInputMode == AltModPrfInputMode::Shared)
		{
			mKeyMultSender.setKeyOts(k, sendOts);
		}
		else
		{
			if (sendOts.size() != 0)
				throw RTE_LOC;
		}
	}

	void mod3BitDecompostion(oc::MatrixView<u16> u, oc::MatrixView<block> u0, oc::MatrixView<block> u1)
	{
		if (u.rows() != u0.rows())
			throw RTE_LOC;
		if (u.rows() != u1.rows())
			throw RTE_LOC;

		if (oc::divCeil(u.cols(), 128) != u0.cols())
			throw RTE_LOC;
		if (oc::divCeil(u.cols(), 128) != u1.cols())
			throw RTE_LOC;

		u64 n = u.rows();
		u64 m = u.cols();

		oc::AlignedUnVector<u8> temp(oc::divCeil(m * 2, 8));
		for (u64 i = 0; i < n; ++i)
		{
			auto iter = temp.data();

			assert(m % 4 == 0);

			for (u64 k = 0; k < m; k += 4)
			{
				assert(u[i][k + 0] < 3);
				assert(u[i][k + 1] < 3);
				assert(u[i][k + 2] < 3);
				assert(u[i][k + 3] < 3);

				// 00 01 10 11 20 21 30 31
				*iter++ =
					(u[i][k + 0] << 0) |
					(u[i][k + 1] << 2) |
					(u[i][k + 2] << 4) |
					(u[i][k + 3] << 6);
			}

			span<u8> out0((u8*)u0.data(i), temp.size() / 2);
			span<u8> out1((u8*)u1.data(i), temp.size() / 2);
			perfectUnshuffle(temp, out0, out1);

#ifndef NDEBUG
			for (u64 j = 0; j < out0.size(); ++j)
			{
				if (out0[j] & out1[j])
					throw RTE_LOC;
			}
#endif
		}
	}


	//macoro::task<> keyMultCorrectionSend(
	//	Request<TritOtSend>& request,
	//	oc::MatrixView<const oc::block> x,
	//	oc::Matrix<oc::block>& y0,
	//	oc::Matrix<oc::block>& y1,
	//	coproto::Socket& sock,
	//	bool debug)
	//{

	//	struct SharedBuffer : span<block>
	//	{
	//		using Container = oc::AlignedUnVector<block>;
	//		SharedBuffer(std::shared_ptr<Container> c, span<typename Container::value_type> v)
	//			: span<typename Container::value_type>(v)
	//			, mCont(c)
	//		{}

	//		std::shared_ptr<Container> mCont;
	//	};

	//	if (request.size() < x.size() * 128)
	//		throw RTE_LOC;
	//	y0.resize(x.rows(), x.cols(), oc::AllocType::Uninitialized);
	//	y1.resize(x.rows(), x.cols(), oc::AllocType::Uninitialized);

	//	std::shared_ptr<oc::AlignedUnVector<block>> delta =
	//		std::make_shared<oc::AlignedUnVector<block>>(2 * x.size());
	//	oc::AlignedUnVector<block> correction;

	//	TritOtSend trit;
	//	u64 j = 0, rem = x.size(), k = 0;
	//	while (rem)
	//	{
	//		co_await request.get(trit);
	//		// the step size
	//		auto min = std::min(rem, trit.size() / 128);

	//		// the buffer holding delta
	//		SharedBuffer di(delta, { delta->data() + j * 2, min * 2 });

	//		// delta lsb and msb
	//		auto d0 = span<block>(di.data(), min);
	//		auto d1 = span<block>(di.data() + min, min);

	//		// the input and outputs
	//		auto xi = span<const block>(x.data() + j, min);
	//		auto y0i = span<block>(y0.data() + j, min);
	//		auto y1i = span<block>(y1.data() + j, min);

	//		correction.resize(min);
	//		co_await sock.recv(correction);

	//		// delta = s0 + s1
	//		mod3Add(d1, d0, trit.mMsb[0], trit.mLsb[0], trit.mMsb[1], trit.mLsb[1]);
	//		// delta = s0 + s1 + x
	//		mod3Add(d1, d0, xi);

	//		// y = -(s_c)
	//		for (u64 i = 0; i < min; ++i)
	//		{
	//			// compute the diff
	//			auto t0 = trit.mLsb[0].data()[i] ^ trit.mLsb[1].data()[i];
	//			auto t1 = trit.mMsb[0].data()[i] ^ trit.mMsb[1].data()[i];

	//			// select either s0 or s1, assign the bits backwards for negation.
	//			y1i.data()[i] = correction.data()[i] & (t0 ^ trit.mLsb[1].data()[i]);
	//			y0i.data()[i] = correction.data()[i] & (t1 ^ trit.mMsb[1].data()[i]);
	//		}

	//		co_await sock.send(std::move(di));

	//		rem -= min;
	//		j += min;
	//	}

	//}

	//macoro::task<> keyMultCorrectionRecv(
	//	Request<TritOtRecv>& request,
	//	oc::MatrixView<const oc::block> x,
	//	oc::Matrix<oc::block>& y0,
	//	oc::Matrix<oc::block>& y1,
	//	coproto::Socket& sock,
	//	bool debug)
	//{
	//	macoro::async_scope asyncScope;

	//	MACORO_TRY{
	//		struct SharedBuffer : span<block>
	//		{
	//			using Container = oc::AlignedUnVector<block>;
	//			SharedBuffer(std::shared_ptr<Container> c, span<typename Container::value_type> v)
	//				: span<typename Container::value_type>(v)
	//				, mCont(c)
	//			{}

	//			std::shared_ptr<Container> mCont;
	//		};

	//		if (request.size() != x.size() * 128)
	//			throw RTE_LOC;
	//		y0.resize(x.rows(), x.cols(), oc::AllocType::Uninitialized);
	//		y1.resize(x.rows(), x.cols(), oc::AllocType::Uninitialized);

	//		std::shared_ptr<oc::AlignedUnVector<block>> correction =
	//			std::make_shared<oc::AlignedUnVector<block>>(x.size());
	//		std::shared_ptr<oc::AlignedUnVector<block>> delta =
	//			std::make_shared<oc::AlignedUnVector<block>>(2 * x.size());


	//		std::vector<std::pair<TritOtRecv, macoro::scoped_task<>>> trits;trits.reserve(request.batchCount());
	//		u64 j = 0, rem = x.size();
	//		while (rem)
	//		{
	//			trits.emplace_back();
	//			auto& [trit, recv] = trits.back();
	//			co_await request.get(trit);

	//			// the step size
	//			auto min = std::min(rem, trit.size() / 128);
	//			// the input
	//			auto xi = span<const block>(x.data() + j, min);
	//			auto ci = SharedBuffer(correction, correction->subspan(j, min));


	//			for (u64 i = 0; i < min; ++i)
	//			{
	//				ci[i] = trit.choice()[i] ^ xi[i];
	//			}

	//			co_await sock.send(std::move(ci));

	//			// schedule the recv operation eagerly.
	//			auto di = SharedBuffer(delta, delta->subspan(j * 2, min * 2));
	//			recv = asyncScope.add(sock.recv(di));


	//			rem -= min;
	//			j += min;
	//		}

	//		j = 0; rem = x.size();
	//		u64 k = 0;
	//		while (rem)
	//		{
	//			auto& [trit, recv] = trits[k++];

	//			auto min = std::min(rem, trit.size() / 128);
	//			co_await std::move(recv);

	//			// delta lsb and msb
	//			auto di = SharedBuffer(delta, delta->subspan(j*2, min*2));
	//			auto d0 = di.subspan(0, min);
	//			auto d1 = di.subspan(min, min);

	//			// the input and outputs
	//			auto xi = span<const block>(x.data() + j, min);
	//			auto y0i = span<block>(y0.data() + j, min);
	//			auto y1i = span<block>(y1.data() + j, min);

	//			// delta = x1 * delta 
	//			for (u64 i = 0; i < min; ++i)
	//			{
	//				d0[i] = d0[i] & xi[i];
	//				d1[i] = d1[i] & xi[i];
	//			}

	//			// y = sb + x * delta
	//			mod3Add(d1, d0, trit.mMsb, trit.mLsb);
	//			// delta = s0 + s1 + x
	//			mod3Add(d1, d0, xi);

	//			// y = -sb
	//			m emcpy(y0i, trit.mMsb);
	//			m emcpy(y1i, trit.mLsb);

	//			//std::cout << "send " << k << std::endl;
	//			//co_await sock.send(std::move(di));

	//			rem -= min;
	//			j += min;
	//		}
	//	}
	//	MACORO_CATCH(ex)
	//	{
	//		co_await sock.close();
	//		co_await asyncScope;
	//	}

	//}


	coproto::task<> AltModWPrfSender::evaluate(
		span<block> x,
		span<block> y,
		coproto::Socket& sock,
		PRNG& prng)
	{

		auto buffer = oc::AlignedUnVector<u8>{};
		auto f = oc::BitVector{};
		auto diff = oc::BitVector{};
		auto ole = BinOleRequest{};
		auto u0 = oc::Matrix<block>{};
		auto u1 = oc::Matrix<block>{};
		auto uu0 = oc::Matrix<block>{};
		auto uu1 = oc::Matrix<block>{};
		auto v = oc::Matrix<block>{};
		auto xk0 = oc::Matrix<block>{};
		auto xk1 = oc::Matrix<block>{};
		auto msg = oc::Matrix<block>{};

		if (y.size() != mInputSize)
			throw std::runtime_error("output length do not match. " LOCATION);

		if (mUseMod2F4Ot)
		{
			if (mMod2F4Req.size() != oc::roundUpTo(y.size(), 128) * AltModPrf::MidSize)
				throw std::runtime_error("do not have enough preprocessing. Call request(...) first. " LOCATION);
		}
		else
		{
			if (mMod2OleReq.size() != oc::roundUpTo(y.size(), 128) * AltModPrf::MidSize * 2)
				throw std::runtime_error("do not have enough preprocessing. Call request(...) first. " LOCATION);
		}

		setTimePoint("DarkMatter.sender.begin");

		mKeyMultRecver.mDebug = mDebug;
		mKeyMultSender.mDebug = mDebug;

		if ((mKeyMode == AltModPrfKeyMode::SenderOnly || mKeyMode == AltModPrfKeyMode::Shared)
			&& mInputMode == AltModPrfInputMode::ReceiverOnly)
		{
			co_await mKeyMultRecver.mult(y.size(), xk0, xk1, sock);
		}
		else
		{

			// plaintext key and shared input is not implemented.
			if (mKeyMode != AltModPrfKeyMode::Shared &&
				mInputMode != AltModPrfInputMode::Shared)
				throw std::runtime_error("unsupported mode combination. " LOCATION);

			if (mKeyMultSender.mOptionalKeyShare.has_value() == false)
				throw RTE_LOC;
			if (mKeyMultRecver.mKey != *mKeyMultSender.mOptionalKeyShare)
				throw RTE_LOC;

			// we need x in a transformed format so that we can do SIMD operations.
			oc::Matrix<block> xt(AltModPrf::KeySize, oc::divCeil(x.size(), 128));
			AltModPrf::expandInput(x, xt);
			if (mDebug)
				mDebugInput = std::vector<block>(x.begin(), x.end());

			auto xkaLsb = oc::Matrix<block>{};
			auto xkaMsb = oc::Matrix<block>{};
			auto xtMsb = oc::Matrix<block>{ xt.rows(), xt.cols(), oc::AllocType::Uninitialized };
			auto xtLsb = oc::Matrix<block>{ xt.rows(), xt.cols(), oc::AllocType::Uninitialized };
			auto sb = sock.fork();

			co_await mConvToF3.convert(xt, sock, xtMsb, xtLsb);

			co_await macoro::when_all_ready(
				mKeyMultRecver.mult(x.size(), xk0, xk1, sock),
				mKeyMultSender.mult(xtLsb, xtMsb, xkaLsb, xkaMsb, sb)
			);

			// xka += xkb
			mod3Add(xk1, xk0, xkaMsb, xkaLsb);
		}

		if (mDebug)
		{
			mDebugXk0 = xk0;
			mDebugXk1 = xk1;
		}

		// Compute u = H * xkShare mod 3
		buffer = {};
		u0.resize(AltModPrf::MidSize, oc::divCeil(y.size(), 128), oc::AllocType::Uninitialized);
		u1.resize(AltModPrf::MidSize, oc::divCeil(y.size(), 128), oc::AllocType::Uninitialized);

		AltModPrf::mACode.encode(xk1, xk0, u1, u0);
		xk0 = {};
		xk1 = {};
		//mtxMultA(std::move(xk1), std::move(xk0), u1, u0);

		if (mDebug)
		{
			mDebugU0 = u0;
			mDebugU1 = u1;
		}

		// Compute v = u mod 2
		v.resize(AltModPrf::MidSize, u0.cols());
		if (mUseMod2F4Ot)
			co_await(mod2OtF4(u0, u1, v, sock));
		else
			co_await(mod2Ole(u0, u1, v, sock));

		if (mDebug)
		{
			mDebugV = v;
		}

		// Compute y = B * v
		compressB(v, y);

		mInputSize = 0;

	}

	void AltModWPrfReceiver::setKeyOts(
		span<std::array<block, 2>> ots,
		std::optional<AltModPrf::KeyType> keyShare,
		span<block> recvOts)
	{
		mKeyMultSender.setKeyOts(keyShare, ots);

		if (mKeyMode == AltModPrfKeyMode::Shared &&
			mInputMode == AltModPrfInputMode::Shared)
		{
			if (!keyShare.has_value())
				throw RTE_LOC;

			mKeyMultRecver.setKeyOts(*keyShare, recvOts);
		}
		else
		{
			if (recvOts.size() != 0)
				throw RTE_LOC;
		}
	}


	coproto::task<> AltModWPrfReceiver::evaluate(
		span<block> x,
		span<block> y,
		coproto::Socket& sock,
		PRNG& prng)
	{

		if (mInputSize == 0)
			throw std::runtime_error("input lengths 0. " LOCATION);

		auto pre = macoro::eager_task<>{};

		if (x.size() != mInputSize)
			throw std::runtime_error("input lengths do not match. " LOCATION);

		if (y.size() != mInputSize)
			throw std::runtime_error("output lengths do not match. " LOCATION);

		if (mUseMod2F4Ot)
		{
			if (mMod2F4Req.size() != oc::roundUpTo(y.size(), 128) * AltModPrf::MidSize)
				throw std::runtime_error("do not have enough preprocessing. Call request(...) first. " LOCATION);
		}
		else
		{
			if (mMod2OleReq.size() != oc::roundUpTo(y.size(), 128) * AltModPrf::MidSize * 2)
				throw std::runtime_error("do not have enough preprocessing. Call request(...) first. " LOCATION);
		}

		// If no one has started the preprocessing, then lets start it.
		//if (mPreproStarted == false)
		//    pre = preprocess() | macoro::make_eager();

		setTimePoint("DarkMatter.recver.begin");

		// we need x in a transformed format so that we can do SIMD operations.
		oc::Matrix<block> xt(AltModPrf::KeySize, oc::divCeil(x.size(), 128));
		AltModPrf::expandInput(x, xt);
		if (mDebug)
			mDebugInput = std::vector<block>(x.begin(), x.end());

		mKeyMultRecver.mDebug = mDebug;
		mKeyMultSender.mDebug = mDebug;

		auto xk0 = oc::Matrix<block>{};
		auto xk1 = oc::Matrix<block>{};
		if ((mKeyMode == AltModPrfKeyMode::SenderOnly || mKeyMode == AltModPrfKeyMode::Shared)
			&& mInputMode == AltModPrfInputMode::ReceiverOnly)
		{
			co_await mKeyMultSender.mult(xt, {}, xk0, xk1, sock);
		}
		else
		{
			// SenderOnly key and shared input is not implemented.
			if (mKeyMode != AltModPrfKeyMode::Shared &&
				mInputMode != AltModPrfInputMode::Shared)
				throw std::runtime_error("unsupported mode combination. SenderOnly key and secret shared input is not implemented. " LOCATION);

			if (mKeyMultSender.mOptionalKeyShare.has_value() == false)
				throw RTE_LOC;

			if (mKeyMultRecver.mKey != *mKeyMultSender.mOptionalKeyShare)
				throw RTE_LOC;

			auto xtMsb = oc::Matrix<block>{ xt.rows(), xt.cols(), oc::AllocType::Uninitialized };
			auto xtLsb = oc::Matrix<block>{ xt.rows(), xt.cols(), oc::AllocType::Uninitialized };
			auto xk0a = oc::Matrix<block>{  };
			auto xk1a = oc::Matrix<block>{  };
			auto sb = sock.fork();

			co_await mConvToF3.convert(xt, sock, xtMsb, xtLsb);

			co_await macoro::when_all_ready(
				mKeyMultSender.mult(xtLsb, xtMsb, xk0a, xk1a, sock),
				mKeyMultRecver.mult(x.size(), xk0, xk1, sb)
			);

			xk1.resize(xk1a.rows(), xk1a.cols());
			xk0.resize(xk0a.rows(), xk0a.cols());
			assert(xk0.size() == xk0a.size());
			assert(xk1.size() == xk1a.size());

			// xk = xka + xkb
			mod3Add(xk1, xk0, xk1a, xk0a);
		}


		if (mDebug)
		{
			mDebugXk0 = xk0;
			mDebugXk1 = xk1;
		}


		// Compute u = H * xkShare mod 3
		oc::Matrix<block>u0(AltModPrf::MidSize, oc::divCeil(x.size(), 128), oc::AllocType::Uninitialized);
		oc::Matrix<block>u1(AltModPrf::MidSize, oc::divCeil(x.size(), 128), oc::AllocType::Uninitialized);
		AltModPrf::mACode.encode(xk1, xk0, u1, u0);
		xk0 = {};
		xk1 = {};

		if (mDebug)
		{
			mDebugU0 = u0;
			mDebugU1 = u1;
		}

		// Compute v = u mod 2
		oc::Matrix<block>v(AltModPrf::MidSize, u0.cols());
		if (mUseMod2F4Ot)
			co_await(mod2OtF4(u0, u1, v, sock));
		else
			co_await(mod2Ole(u0, u1, v, sock));

		if (mDebug)
		{
			mDebugV = v;
		}

		// Compute y = B * v
		compressB(v, y);
		mInputSize = 0;

	}




	// The parties input a sharing of the u=(u0,u1) such that 
	// 
	//   u = u0 + u1 mod 3
	// 
	// When looking at the truth table of u mod 2 we have
	// 
	//           u1
	//          0 1 2
	//         ________
	//      0 | 0 1 0
	//   u0 1 | 1 0 0 
	//      2 | 0 0 1
	//   
	// Logically, what we are going to do is a 1-out-of-3
	// OT. The PrfSender with u0 will use select the row of
	// this table based on u0. For example, if u0=0 then the 
	// truth table reduces to
	// 
	//   0 1 0
	// 
	// where the PrfReceiver should use the OT to pick up
	// the element indexed bu u1. For example, they should pick up 
	// 1 iff u1 = 1.
	// 
	// To maintain security, we need to give the PrfReceiver a sharing
	// of this value, not the value itself. The PrfSender will pick a random mask
	// 
	//   r
	// 
	// and then the PrfReceiver should learn that table above XOR r.
	// 
	// We can build a 1-out-of-3 OT from OLE. Each mod2 / 1-out-of-3 OT consumes 2 
	// binary OLE's. A single OLE consists of PrfSender holding 
	// 
	//     x0, y0
	// 
	// the PrfReceiver holding
	// 
	//     x1, y1
	// 
	// such that (x0+x1) = (y0*y1). We will partially derandomize these
	// by allowing the PrfReceiver to change their y1 to be a chosen
	// value, c. That is, the parties want to hold correlation
	// 
	//    (x0',y0',x1', c)
	// 
	// where x0,x1,y0 are random and c is chosen. This is done by sending
	// 
	//   d = (y1+c)
	// 
	// and the PrfSender updates their share as
	// 
	//   x0' = x0 + y0 * d
	// 
	// The parties output (x0',y0,x1,c). Observe parties hold the correlation
	// 
	//   x1 + x0'                   = y0 * c
	//   x1 + x0 + y0 * d           = y0 * c
	//   x1 + x0 + y0 * (y1+c)      = y0 * c
	//   x1 + x0 + y0 * y1 + y0 * c = y0 * c
	//                       y0 * c = y0 * c
	//
	// Ok, now let us perform the mod 2 operations. As state, this 
	// will consume 2 OLEs. Let these be denoted as
	// 
	//   (x0,x1,y0,y1), (x0',x1',y0',y1')
	//
	// These have not been derandomized yet. To get an 1-out-of-3 OT, we
	// will derandomize them using the PrfReceiver's u1. This value is 
	// represented using two bits (u10,u11) such that u1 = u10 + 2 * u11
	// 
	// We will derandomize (x0,x1,y0,y1) using u10 and (x0',x1',y0',y1') 
	// using u11. Let us redefine these correlations as 
	// 
	//   (x0,x1,y0,u10), (x0',x1',y0',u11)
	// 
	// That is, we also redefined x0,x0' accordingly.
	// 
	// We will define the random OT strings (in tms case x1 single bit)
	// as 
	//    
	//    m0 = x0      + x0'
	//    m1 = x0 + y0 + x0'
	//    m2 = x0      + x0' + y0'
	// 
	// Note that 
	//  - when u10 = u11 = 0, then x1=x0, x1'=x0' and therefore
	//    the PrfReceiver knows m0. m1,m2 is uniform due to y0, y0' being 
	//    uniform, respectively. 
	// - When u10 = 1, u11 = 0, then x1 = x0 + y0 and x1' = x0 and therefore 
	//   PrfReceiver knows m1 = x1 + x1' = (x0 + y0) + x0'. m0 is uniform because 
	//   x0 = x1 + y0 and y0 is uniform given x1. m2 is uniform because y0' 
	//   is uniform given x1. 
	// - Finally, when u10 = 0, u11 = 1, the same basic case as above applies.
	// 
	// 
	// these will be used to mask the truth table T. That is, the PrfSender
	// will sample x1 mask r and send
	// 
	//   t0 = m0 + T[u0, 0] + r
	//   t1 = m1 + T[u0, 1] + r
	//   t2 = m2 + T[u0, 2] + r
	// 
	// The PrfReceiver can therefore compute
	// 
	//   z1 = t_u1 + m_u1
	//      = T[u1, u1] + r
	//      = (u mod 2) + r
	// 
	// and the PrfSender can compute
	//  
	//   z0 = r
	// 
	// and therefor we have z0+z1 = u mod 2.
	// 
	// As an optimization, we dont need to send t0. The idea is that if
	// the receiver want to learn T[u0, 0], then they can set their share
	// as m0. That is,
	// 
	//   z1 = (u1 == 0) ? m0 : t_u1 + m_u1
	//      = u10 * t_u1 + mu1
	// 
	// The sender now needs to define r appropriately. In particular, 
	// 
	//   r = m0 + T[u0, 0]
	// 
	// In the case of u1 = 0, z1 = m0, z0 = r + T[u0,0], and therefore we 
	// get the right result. The other cases are the same with the randomness
	// of the mast r coming from m0.
	// 
	//
	// u has 256 rows
	// each row holds 2bit values
	// 
	// out will have 256 rows.
	// each row will hold packed bits.
	// 
	macoro::task<> AltModWPrfSender::mod2Ole(
		oc::MatrixView<block> u0,
		oc::MatrixView<block> u1,
		oc::MatrixView<block> out,
		coproto::Socket& sock)
	{
		auto triple = BinOle{};
		auto tIdx = u64{};
		auto tSize = u64{};
		auto i = u64{};
		auto j = u64{};
		auto rows = u64{};
		auto cols = u64{};
		auto step = u64{};
		auto end = u64{};
		auto buff = oc::AlignedUnVector<block>{};
		auto outIter = (block*)nullptr;
		auto u0Iter = (block*)nullptr;
		auto u1Iter = (block*)nullptr;
		if (mUseMod2F4Ot)
		{
			std::cout << "mUseMod2F4Ot == true but call mod2Ole. " << LOCATION << std::endl;
			std::terminate();
		}

		if (out.rows() != u0.rows())
			throw RTE_LOC;
		if (out.rows() != u1.rows())
			throw RTE_LOC;
		if (out.cols() != u0.cols())
			throw RTE_LOC;
		if (out.cols() != u1.cols())
			throw RTE_LOC;

		tIdx = 0;
		tSize = 0;
		rows = u0.rows();
		cols = u0.cols();

		outIter = out.data();
		u0Iter = u0.data();
		u1Iter = u1.data();
		for (i = 0; i < rows; ++i)
		{
			for (j = 0; j < cols; )
			{

				if (tIdx == tSize)
				{
					co_await(mMod2OleReq.get(triple));

					tSize = triple.mAdd.size();
					tIdx = 0;
					buff.resize(tSize);
					co_await(sock.recv(buff));
				}


				// we have (cols - j) * 128 elems left in the row.
				// we have (tSize - tIdx) * 128 oles left
				// each elem requires 2 oles
				// 
				// so the amount we can do this iteration is 
				step = std::min<u64>(cols - j, (tSize - tIdx) / 2);
				end = step + j;
				for (; j < end; j += 1, tIdx += 2)
				{
					// we have x1, y1, s.t. x0 + x1 = y0 * y1
					auto x = &triple.mAdd.data()[tIdx];
					auto y = &triple.mMult.data()[tIdx];
					auto d = &buff.data()[tIdx];

					// x1[0] = x1[0] ^ (y1[0] * d[0])
					//       = x1[0] ^ (y1[0] * (u0[0] ^ y0[0]))
					//       = x1[0] ^ (y[0] * u0[0])
					for (u64 k = 0; k < 2; ++k)
					{
						x[k] = x[k] ^ (y[k] & d[k]);
					}

					block m0, m1, m2, t0, t1, t2;
					m0 = x[0] ^ x[1];
					m1 = m0 ^ y[0];
					m2 = m0 ^ y[1];

					//           u1
					//          0 1 2
					//         ________
					//      0 | 0 1 0
					//   u0 1 | 1 0 0 
					//      2 | 0 0 1
					//t0 = hi0 + T[u0,0] 
					//   = hi0 + u0(i,j)  

					assert(u0Iter == &u0(i, j));
					assert(u1Iter == &u1(i, j));
					assert((u0(i, j) & u1(i, j)) == oc::ZeroBlock);

					t0 = m0 ^ *u0Iter;
					t1 = t0 ^ m1 ^ *u0Iter ^ *u1Iter ^ oc::AllOneBlock;
					t2 = t0 ^ m2 ^ *u1Iter;

					++u0Iter;
					++u1Iter;

					//if (mDebug)// && i == mPrintI && (j == (mPrintJ / 128)))
					//{
					//    auto mPrintJ = 0;
					//    auto bitIdx = mPrintJ % 128;
					//    std::cout << j << " m  " << bit(m0, bitIdx) << " " << bit(m1, bitIdx) << " " << bit(m2, bitIdx) << std::endl;
					//    std::cout << j << " u " << bit(u1(i, j), bitIdx) << bit(u0(i, j), bitIdx) << " = " <<
					//        (bit(u1(i, j), bitIdx) * 2 + bit(u0(i, j), bitIdx)) << std::endl;
					//    std::cout << j << " r  " << bit(m0, bitIdx) << std::endl;
					//    std::cout << j << " t  " << bit(t0, bitIdx) << " " << bit(t1, bitIdx) << " " << bit(t2, bitIdx) << std::endl;
					//}

					// r
					assert(outIter == &out(i, j));
					*outIter++ = t0;
					d[0] = t1;
					d[1] = t2;
				}

				if (tIdx == tSize)
				{
					co_await(sock.send(std::move(buff)));
				}
			}
		}

		assert(buff.size() == 0);

	}




	macoro::task<> AltModWPrfReceiver::mod2Ole(
		oc::MatrixView<block> u0,
		oc::MatrixView<block> u1,
		oc::MatrixView<block> out,
		coproto::Socket& sock)
	{
		auto triple = std::vector<BinOle>{};
		auto tIter = std::vector<BinOle>::iterator{};
		auto tIdx = u64{};
		auto tSize = u64{};
		auto i = u64{};
		auto j = u64{};
		auto step = u64{};
		auto rows = u64{};
		auto end = u64{};
		auto cols = u64{};
		auto buff = oc::AlignedUnVector<block>{};
		auto add = span<block>{};
		auto mlt = span<block>{};
		auto outIter = (block*)nullptr;
		auto u0Iter = (block*)nullptr;
		auto u1Iter = (block*)nullptr;
		auto ec = macoro::result<void, std::exception_ptr>{};

		if (mUseMod2F4Ot)
		{
			std::cout << "mUseMod2F4Ot == true but call mod2Ole. " << LOCATION << std::endl;
			std::terminate();
		}

		triple.reserve(mMod2OleReq.batchCount());
		tIdx = 0;
		tSize = 0;

		// the format of u is that it should have AltModWPrf::MidSize rows.
		rows = u0.rows();

		// cols should be the number of inputs.
		cols = u0.cols();

		// we are performing mod 2. u0 is the lsb, u1 is the msb. these are packed into 128 bit blocks. 
		// we then have a matrix of these with `rows` rows and `cols` columns. We mod requires
		// 2 OLEs. So in total we need rows * cols * 128 * 2 OLEs.
		assert(mMod2OleReq.size() == rows * cols * 128 * 2);

		u0Iter = u0.data();
		u1Iter = u1.data();
		for (i = 0; i < rows; ++i)
		{
			for (j = 0; j < cols;)
			{

				if (tSize == tIdx)
				{

					triple.emplace_back();
					co_await(mMod2OleReq.get(triple.back()));

					tSize = triple.back().mAdd.size();
					tIdx = 0;
					buff.resize(tSize);
				}

				step = std::min<u64>(cols - j, (tSize - tIdx) / 2);
				end = step + j;

				for (; j < end; ++j, tIdx += 2)
				{
					auto y = &triple.back().mMult.data()[tIdx];
					auto b = &buff.data()[tIdx];
					assert(u0Iter == &u0(i, j));
					assert(u1Iter == &u1(i, j));
					b[0] = *u0Iter ^ y[0];
					b[1] = *u1Iter ^ y[1];

					++u0Iter;
					++u1Iter;
				}

				if (tSize == tIdx)
				{
					co_await(sock.send(std::move(buff)));
					TODO("clear mult");
					//triple.back().clear();
				}
			}
		}

		if (buff.size())
			co_await(sock.send(std::move(buff)));

		tIdx = 0;
		tSize = 0;
		tIter = triple.begin();
		outIter = out.data();
		u0Iter = u0.data();
		u1Iter = u1.data();
		for (i = 0; i < rows; ++i)
		{
			for (j = 0; j < cols; )
			{

				if (tIdx == tSize)
				{

					tIdx = 0;
					tSize = tIter->mAdd.size();
					add = tIter->mAdd;
					++tIter;
					buff.resize(tSize);
					co_await(sock.recv(buff));
				}

				step = std::min<u64>(cols - j, (tSize - tIdx) / 2);
				end = step + j;

				for (; j < end; ++j, tIdx += 2)
				{

					assert((u0(i, j) & u1(i, j)) == oc::ZeroBlock);
					assert(u0Iter == &u0(i, j));
					assert(u1Iter == &u1(i, j));

					// if u = 0, w = hi0
					// if u = 1, w = hi1 + t1
					// if u = 2, w = m2 + t2
					block w =
						(*u0Iter++ & buff.data()[tIdx + 0]) ^ // t1
						(*u1Iter++ & buff.data()[tIdx + 1]) ^ // t2
						add.data()[tIdx + 0] ^ add.data()[tIdx + 1];// m_u

					//if (mDebug)// && i == mPrintI && (j == (mPrintJ / 128)))
					//{
					//    auto mPrintJ = 0;
					//    auto bitIdx = mPrintJ % 128;
					//    std::cout << j << " u " << bit(u1(i, j), bitIdx) << bit(u0(i, j), bitIdx) << " = " <<
					//        (bit(u1(i, j), bitIdx) * 2 + bit(u0(i, j), bitIdx)) << std::endl;
					//    std::cout << j << " t  _ " << bit(buff[tIdx + 0], bitIdx) << " " << bit(buff[tIdx + 1], bitIdx) << std::endl;
					//    std::cout << j << " w  " << bit(w, bitIdx) << std::endl;
					//}

					assert(outIter == &out(i, j));
					*outIter++ = w;
				}
			}
		}
	}






	// The parties input a sharing (u,v) such that 
	// 
	//   u + v mod 3
	// 
	// is the true value. When looking at the truth table of u mod 2 we have
	// 
	//            u
	//          0 1 2
	//         ________
	//      0 | 0 1 0
	//   v  1 | 1 0 0 
	//      2 | 0 0 1
	//   
	// Logically, what we are going to do is a 1-out-of-3
	// OT. The PrfSender with v will use select the row of
	// this table based on v. For example, if v=0 then the 
	// truth table reduces to
	// 
	//   0 1 0
	// 
	// where the PrfReceiver should use the OT to pick up
	// the element indexed by u. For example, they should pick up 
	// 1 iff u = 1.
	// 
	// To maintain security, we need to give the PrfReceiver a sharing
	// of this value, not the value itself. The PrfSender will pick a random
	// share
	// 
	//   r
	// 
	// and then the PrfReceiver should learn that table above XOR r. Let v0 and v1 
	// be the lsb and msb of v. The truth table can be computed as 
	// 
	//  T[v,0] = v0
	//  T[v,1] = ~(v0 ^ v1)
	//  T[v,2] = v1
	// 
	// and so we will sent via a 1-oo-3 OT the messages  
	// 
	//  t0 = r + T[v,0], 
	//  t1 = r + T[v,1], 
	//  t2 = r + T[v,2]
	// 
	// As an optimization, we dont need to send t0. The idea is that if
	// the receiver want to learn T[v, 0], then they can set their share
	// as OT string m0. The sender will set their output share as
	// 
	// z1 = m0 + T[v,0]
	// 
	// The sender now needs to define r appropriately. 
	macoro::task<> AltModWPrfSender::mod2OtF4(
		oc::MatrixView<block> v0,
		oc::MatrixView<block> v1,
		oc::MatrixView<block> out,
		coproto::Socket& sock)
	{
		auto ots = F4BitOtSend{};
		auto i = u64{};
		auto j = u64{};
		auto rows = u64{};
		auto cols = u64{};
		auto step = u64{};
		auto end = u64{};
		auto remaining = u64{};
		auto buff = oc::AlignedUnVector<block>{};
		auto outIter = (block*)nullptr;
		auto v0Iter = (block*)nullptr;
		auto v1Iter = (block*)nullptr;
		auto otEnd = (block*)nullptr;
		auto derand = (block*)nullptr;
		auto derandEnd = (block*)nullptr;
		auto otIter = std::array<block*, 4>{nullptr, nullptr, nullptr, nullptr};
		if (!mUseMod2F4Ot)
		{
			std::cout << "mUseMod2F4Ot == false but call mod2OtF4. " << LOCATION << std::endl;
			std::terminate();
		}
		if (out.rows() != v0.rows())
			throw RTE_LOC;
		if (out.rows() != v1.rows())
			throw RTE_LOC;
		if (out.cols() != v0.cols())
			throw RTE_LOC;
		if (out.cols() != v1.cols())
			throw RTE_LOC;

		rows = v0.rows();
		cols = v0.cols();
		remaining = rows * cols;

		outIter = out.data();
		v0Iter = v0.data();
		v1Iter = v1.data();
		for (i = 0; i < rows; ++i)
		{
			for (j = 0; j < cols; )
			{

				if (otIter[0] == otEnd)
				{
					co_await(mMod2F4Req.get(ots));

					otEnd = ots.mOts[0].data() + ots.mOts[0].size();
					for (u64 k = 0; k < 4; ++k)
						otIter[k] = ots.mOts[k].data();

					buff.resize(std::min<u64>(ots.mOts[0].size(), remaining) * 2);
					remaining -= buff.size() / 2;

					co_await(sock.recv(buff));
					derand = buff.data();
					derandEnd = derand + buff.size();
				}


				// we have (cols - j) * 128 elems left in the row.
				// we have (tSize - tIdx) * 128 oles left
				// each elem requires 2 oles
				// 
				// so the amount we can do this iteration is 
				step = std::min<u64>(cols - j, (derandEnd - derand) / 2);
				end = step + j;
				for (; j < end; ++j)
				{

					assert(v0Iter == &v0(i, j));
					assert(v1Iter == &v1(i, j));
					assert((v0(i, j) & v1(i, j)) == oc::ZeroBlock);


					auto swap = [](block* l0, block* l1, block c)
						{
							auto diff = *l0 ^ *l1;
							*l0 = *l0 ^ (c & diff);
							*l1 = *l0 ^ diff;
						};

					// derandomize the OT strings based on their choice values derand
					swap(otIter[0], otIter[1], derand[0]);
					swap(otIter[2], otIter[3], derand[0]);
					swap(otIter[0], otIter[2], derand[1]);
					swap(otIter[1], otIter[3], derand[1]);

					//            u
					//          0 1 2
					//         ________
					//      0 | 0 1 0
					//   v  1 | 1 0 0 
					//      2 | 0 0 1

					// the shared value if u=0
					auto Tv0 = *v0Iter;

					// the shared value if u=1
					auto Tv1 = ~(*v0Iter ^ *v1Iter);

					// the shared value if u=2
					auto Tv2 = *v1Iter;

					assert(outIter == &out(i, j));

					// outShare = T[v,0] ^ ot_0. They will have ot_1 which xors with this to T[v,0]
					*outIter = Tv0 ^ *otIter[0];

					// t1 = Enc( T[v, 1] ^ outShare )
					auto t1 = Tv1 ^ *outIter ^ *otIter[1];

					// t2 = Enc( T[u, 2] ^ outShare )
					auto t2 = Tv2 ^ *outIter ^ *otIter[2];

					//if (mDebug)// && i == mPrintI && (j == (mPrintJ / 128)))
					//{
					//    auto mPrintJ = 0;
					//    auto bitIdx = mPrintJ % 128;
					//	std::cout << j << " v  " << bit(v1, bitIdx) << bit(v0, bitIdx) << std::endl;
					//	std::cout << j << " m  " << bit(Tv0, bitIdx) << " " << bit(Tv1, bitIdx) << " " << bit(Tv2, bitIdx) << std::endl;
					//	std::cout << j << " ot " << bit(*otIter[0], bitIdx) << " " << bit(*otIter[0], bitIdx) << " " << bit(*otIter[0], bitIdx) << std::endl;
					//	std::cout << j << " t  " << bit(t1, bitIdx) << " " << bit(t2, bitIdx) << std::endl;
					//    std::cout << j << " r  " << bit(*outIter, bitIdx) << std::endl;
					//}

					// r
					derand[0] = t1;
					derand[1] = t2;

					++v0Iter;
					++v1Iter;
					++outIter;
					derand += 2;
					for (u64 k = 0; k < 4; ++k)
						++otIter[k];
				}

				if (derandEnd == derand)
				{
					co_await(sock.send(std::move(buff)));
				}
			}
		}

		assert(buff.size() == 0);

	}



	macoro::task<> AltModWPrfReceiver::mod2OtF4(
		oc::MatrixView<block> u0,
		oc::MatrixView<block> u1,
		oc::MatrixView<block> out,
		coproto::Socket& sock)
	{
		auto ots = std::vector<F4BitOtRecv>{};
		auto tIter = std::vector<F4BitOtRecv>::iterator{};
		auto i = u64{};
		auto j = u64{};
		auto step = u64{};
		auto rows = u64{};
		auto cols = u64{};
		auto end = u64{};
		auto remaining = u64{};
		auto buff = oc::AlignedUnVector<block>{};
		auto outIter = (block*)nullptr;
		auto otIter = (block*)nullptr;
		auto lsbIter = (block*)nullptr;
		auto msbIter = (block*)nullptr;
		auto u0Iter = (block*)nullptr;
		auto u1Iter = (block*)nullptr;
		auto derand = (block*)nullptr;
		auto derandEnd = (block*)nullptr;
		if (!mUseMod2F4Ot)
		{
			std::cout << "mUseMod2F4Ot == false but call mod2OtF4. " << LOCATION << std::endl;
			std::terminate();
		}

		ots.reserve(mMod2F4Req.batchCount());

		// the format of u is that it should have AltModWPrf::MidSize rows.
		rows = u0.rows();

		// cols should be the number of inputs.
		cols = u0.cols();

		remaining = rows * cols;

		// we are performing mod 2. u0 is the lsb, u1 is the msb. these are packed into 128 bit blocks. 
		// we then have a matrix of these with `rows` rows and `cols` columns. We mod requires
		// 2 OLEs. So in total we need rows * cols * 128 * 2 OLEs.
		assert(mMod2F4Req.size() == rows * cols * 128);

		u0Iter = u0.data();
		u1Iter = u1.data();
		for (i = 0; i < rows; ++i)
		{
			for (j = 0; j < cols;)
			{

				if (derandEnd == derand)
				{

					ots.emplace_back();
					co_await(mMod2F4Req.get(ots.back()));
					lsbIter = ots.back().mChoiceLsb.data();
					msbIter = ots.back().mChoiceMsb.data();

					buff.resize(std::min<u64>(ots.back().mChoiceLsb.size(), remaining) * 2);
					remaining -= buff.size() / 2;
					derand = buff.data();
					derandEnd = derand + buff.size();
				}

				step = std::min<u64>(cols - j, (derandEnd - derand) / 2);
				end = step + j;

				for (; j < end; ++j)
				{
					assert(u0Iter == &u0(i, j));
					assert(u1Iter == &u1(i, j));
					derand[0] = *u0Iter++ ^ *lsbIter++;
					derand[1] = *u1Iter++ ^ *msbIter++;

					derand += 2;
				}

				if (derandEnd == derand)
				{
					co_await(sock.send(std::move(buff)));
				}
			}
		}

		assert(buff.size() == 0);

		tIter = ots.begin();
		outIter = out.data();
		u0Iter = u0.data();
		u1Iter = u1.data();
		derand = nullptr;
		derandEnd = nullptr;
		remaining = rows * cols;
		for (i = 0; i < rows; ++i)
		{
			for (j = 0; j < cols; )
			{

				if (derand == derandEnd)
				{
					otIter = tIter->mOts.data();
					buff.resize(std::min<u64>(tIter->mOts.size(), remaining) * 2);
					remaining -= buff.size() / 2;
					co_await(sock.recv(buff));

					derand = buff.data();
					derandEnd = derand + buff.size();
					++tIter;
				}

				step = std::min<u64>(cols - j, (derandEnd - derand) / 2);
				end = step + j;

				for (; j < end; ++j)
				{

					assert((u0(i, j) & u1(i, j)) == oc::ZeroBlock);
					assert(u0Iter == &u0(i, j));
					assert(u1Iter == &u1(i, j));
					assert(derand + 1 < derandEnd);
					assert(outIter == &out(i, j));
					assert(otIter < (tIter[-1].mOts.data() + tIter[-1].mOts.size()));

					// if u = 0, w = hi0
					// if u = 1, w = hi1 + t1
					// if u = 2, w = m2 + t2
					block w =
						(*u0Iter++ & derand[0]) ^ // t1
						(*u1Iter++ & derand[1]) ^ // t2
						*otIter++;// m_u

					//if (mDebug)// && i == mPrintI && (j == (mPrintJ / 128)))
					//{
					//    auto mPrintJ = 0;
					//    auto bitIdx = mPrintJ % 128;
					//    std::cout << j << " u " << bit(u1(i, j), bitIdx) << bit(u0(i, j), bitIdx) << std::endl;
					//    std::cout << j << " t  _ " << bit(derand[0], bitIdx) << " " << bit(derand[1], bitIdx) << std::endl;
					//    std::cout << j << " w  " << bit(w, bitIdx) << std::endl;
					//}

					*outIter++ = w;
					derand += 2;

				}
			}
		}

	}



}