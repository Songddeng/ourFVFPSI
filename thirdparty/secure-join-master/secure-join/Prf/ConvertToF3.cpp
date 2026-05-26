#include "ConvertToF3.h"
#include "macoro/async_scope.h"
#include "mod3.h"
#include "AltModSimd.h"

namespace secJoin
{
	macoro::task<> ConvertToF3Recver::convert(
		span<const block> x,
		coproto::Socket& sock,
		span<block> y1,
		span<block> y0)
	{

		if (y1.size() != x.size())
			throw RTE_LOC;
		if (y0.size() != x.size())
			throw RTE_LOC;
		if (mRequest.size() < x.size())
			throw RTE_LOC;
		macoro::async_scope asyncScope;

		MACORO_TRY{
			struct SharedBuffer : span<block>
			{
				using Container = oc::AlignedUnVector<block>;
				SharedBuffer(std::shared_ptr<Container> c, span<typename Container::value_type> v)
					: span<typename Container::value_type>(v)
					, mCont(c)
				{}

				std::shared_ptr<Container> mCont;
			};

			auto& request = mRequest;
			if (request.size() != x.size() * 128)
				throw RTE_LOC;

			auto correction =
				std::make_shared<oc::AlignedUnVector<block>>(x.size());
			auto delta =
				std::make_shared<oc::AlignedUnVector<block>>(2 * x.size());

			std::vector<std::pair<TritOtRecv, macoro::scoped_task<>>> trits;
			trits.reserve(request.batchCount());

			// given input share 
			//     x0                     x1
			// 
			// and OTs
			//    s0,s1 in F3             c in F2, sc in F3
			// 
			// the protocol is
			//							  cor = c ^ x1
			//              cor
			//   <-------------------------
			//	if(cor) swap(s0,s1);
			// 
			//  delta = s0 - s1 + (1 - x0) in F3
			// 
			//           delta
			//    ------------------------>
			// 
			//  y0 = -s0+x0              y1 = sc + delta * x1
			//  
			u64 j = 0, rem = x.size();
			while (rem)
			{
				trits.emplace_back();
				auto& [trit, recv] = trits.back();
				co_await request.get(trit);

				// the step size
				auto min = std::min(rem, trit.size() / 128);
				// the input
				auto xi = span<const block>(x.data() + j, min);
				auto ci = SharedBuffer(correction, correction->subspan(j, min));

				for (u64 i = 0; i < min; ++i)
				{
					ci.data()[i] = trit.choice().data()[i] ^ xi.data()[i];
				}

				//if (printIdx >= j * 128 && printIdx < (j + min) * 128)
				//{
				//	auto p = printIdx - j * 128;
				//	std::cout << "c[" << printIdx << "] " << bit(trit.choice().data(), p)
				//		<< " ^ x1[" << printIdx << "] " << bit(xi.data(), p)
				//		<< " = cor[" << printIdx << "] " << bit(ci.data(), p)
				//		<< "\n --------------------------------------"
				//		<< std::endl;
				//}

				co_await sock.send(std::move(ci));

				// schedule the recv operation eagerly.
				auto di = SharedBuffer(delta, delta->subspan(j * 2, min * 2));
				recv = asyncScope.add(sock.recv(di));

				rem -= min;
				j += min;
			}

			j = 0; rem = x.size();
			u64 k = 0;
			while (rem)
			{
				auto& [trit, recv] = trits[k++];

				auto min = std::min(rem, trit.size() / 128);
				co_await std::move(recv);

				// delta lsb and msb
				auto di = SharedBuffer(delta, delta->subspan(j * 2, min * 2));
#ifdef NDEBUG
				auto d0 = di.data();
				auto d1 = di.data() + min;
				auto xj = x.data() + j;
				auto y0j = y0.data() + j;
				auto y1j = y1.data() + j;
#else
				auto d0 = di.subspan(0, min);
				auto d1 = di.subspan(min, min);
				auto xj = span<const block>(x.data() + j, min);
				auto y0j = span<block>(y0.data() + j, min);
				auto y1j = span<block>(y1.data() + j, min);
#endif // NDEBUG

				//if (j == 0)
				//{
				//	auto p = printIdx - j * 128;
				//	std::cout << "d[" << printIdx << "] " << (bit(d0.data(), p) + 2 * bit(d1.data(), p))
				//		<< std::endl;
				//}

				for (u64 i = 0; i < min; ++i)
				{
					// delta = x1 * delta 
					d0[i] = d0[i] & xj[i];
					d1[i] = d1[i] & xj[i];
					// y1 = sc + delta * x1
					mod3Add(y1j[i], y0j[i], d1[i], d0[i], trit.mMsb[i], trit.mLsb[i]);
				}

				//if (printIdx >= j * 128 && printIdx < (j + min) * 128)
				//{
				//	auto p = printIdx - j * 128;
				//	std::cout
				//		<< "dx[" << printIdx << "] " << (bit(d0.data(), p) + 2 * bit(d1.data(), p))
				//		<< " + sc[" << printIdx << "] " << (bit(trit.mLsb.data(), p) + 2 * bit(trit.mMsb.data(), p))
				//		<< " = y1[" << printIdx << "] " << (bit(y0j.data(), p) + 2 * bit(y1j.data(), p))
				//		<< "\n --------------------------------------"
				//		<< std::endl;
				//}

				rem -= min;
				j += min;
			}
		}
		MACORO_CATCH(ex)
		{
			co_await sock.close();
			co_await asyncScope;
		}
	}

	macoro::task<> ConvertToF3Sender::convert(
		span<const block> x,
		coproto::Socket& sock,
		span<block> y1, span<block> y0)
	{
		if (y1.size() != x.size())
			throw RTE_LOC;
		if (y0.size() != x.size())
			throw RTE_LOC;
		if (mRequest.size() < x.size())
			throw RTE_LOC;

		struct SharedBuffer : span<block>
		{
			using Container = oc::AlignedUnVector<block>;
			SharedBuffer(std::shared_ptr<Container> c, span<typename Container::value_type> v)
				: span<typename Container::value_type>(v)
				, mCont(c)
			{}

			std::shared_ptr<Container> mCont;
		};
		auto& request = mRequest;

		if (request.size() < x.size() * 128)
			throw RTE_LOC;

		std::shared_ptr<oc::AlignedUnVector<block>> delta =
			std::make_shared<oc::AlignedUnVector<block>>(2 * x.size());
		oc::AlignedUnVector<block> correction;

		TritOtSend trit;
		u64 j = 0, rem = x.size();
		while (rem)
		{
			co_await request.get(trit);
			// the step size
			auto min = std::min(rem, trit.size() / 128);

			// the buffer holding delta
			SharedBuffer di(delta, { delta->data() + j * 2, min * 2 });
			correction.resize(min);
			co_await sock.recv(correction);
#ifdef  NDEBUG

			auto d0 = di.data();
			auto d1 = di.data() + min;
			auto xi = x.data() + j;
			auto y0i =y0.data() + j;
			auto y1i =y1.data() + j;
			auto cr = correction.data();
#else
			// delta lsb and msb
			auto d0 = span<block>(di.data(), min);
			auto d1 = span<block>(di.data() + min, min);
			auto xi = span<const block>(x.data() + j, min);
			auto y0i = span<block>(y0.data() + j, min);
			auto y1i = span<block>(y1.data() + j, min);
			auto cr = span<block>(correction);
#endif // NDEBUG

			// given input share 
			//     x0                     x1
			// 
			// and OTs
			//    s0,s1 in F3             c in F2, sc in F3
			// 
			// the protocol is
			//							  cor = c ^ x1
			//              cor
			//   <-------------------------
			//	if(cor) swap(s0,s1);
			// 
			//  delta = s0 - s1 + (1 - x0) in F3
			// 
			//           delta
			//    ------------------------>
			// 
			//  y0 = -s0+x0              y1 = sc + delta * x1
			//  
			for (u64 i = 0; i < min; ++i)
			{

				// compute the diff
				auto tLsb = trit.mLsb[0].data()[i] ^ trit.mLsb[1].data()[i];
				auto tMsb = trit.mMsb[0].data()[i] ^ trit.mMsb[1].data()[i];

				//  if(cor) swap(s1,s0)
				auto s0Lsb = (cr[i] & tLsb) ^ trit.mLsb[0].data()[i];
				auto s0Msb = (cr[i] & tMsb) ^ trit.mMsb[0].data()[i];
				auto s1Lsb = s0Lsb ^ tLsb;
				auto s1Msb = s0Msb ^ tMsb;
				//auto xi = x[i];

				// delta = s0 - s1
				mod3Sub(d1[i], d0[i], s0Msb, s0Lsb, s1Msb, s1Lsb);

				block onePlusX1 = xi[i], onePlusX0 = ~xi[i];

				// delta = s0 - s1 + (1-2x0)
				//       = s0 - s1 + 1 + x0
				mod3Add(d1[i], d0[i], d1[i], d0[i], onePlusX1, onePlusX0);

				// y0 = -s0 + x0
				mod3Add(y1i[i], y0i[i], s0Lsb, s0Msb, xi[i]);
				 
				//if (printIdx >= j * 128 && printIdx < (j + min) * 128)
				//{
				//	auto p = printIdx - j * 128;
				//	if (i == p / 128)
				//	{
				//		std::cout
				//			<< "s0[" << printIdx << "] " << (bit(trit.mLsb[0].data(), p) + 2 * bit(trit.mMsb[0].data(), p)) << std::endl
				//			<< "s1[" << printIdx << "] " << (bit(trit.mLsb[1].data(), p) + 2 * bit(trit.mMsb[1].data(), p)) << std::endl
				//			<< "x0[" << printIdx << "] " << (bit(xi.data(), p)) << std::endl;
				//		std::cout
				//			<< "(s0-s1+(1-x0))[" << printIdx << "] " << (bit(d0.data(), p) + 2 * bit(d1.data(), p)) << std::endl;
				//		std::cout
				//			<< " x0[" << printIdx << "] " << (bit(xi.data(), p))
				//			<< " - s0[" << printIdx << "] " << (bit(trit.mLsb[0].data(), p) + 2 * bit(trit.mMsb[0].data(), p))
				//			<< " = y0[" << printIdx << "] " << (bit(y0i.data(), p) + 2 * bit(y1i.data(), p))
				//			<< "\n --------------------------------------"
				//			<< std::endl;
				//	}
				//}
			}

			co_await sock.send(std::move(di));
			rem -= min;
			j += min;
		}
	}
}