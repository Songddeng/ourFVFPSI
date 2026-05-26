#include "CorGenerator_Test.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Prf/AltModSimd.h"
using namespace secJoin;

void CorGenerator_F4BitOt_Test(const oc::CLP& cmd)
{

	u64 n = (1ull << 16) + 3234;

	for (auto mock : { false, true })
	{

		PRNG prng(oc::ZeroBlock);

		auto sock = coproto::LocalAsyncSocket::makePair();
		CorGenerator send;
		CorGenerator recv;
		send.init(std::move(sock[0]), prng, 0, 2, 1 << 18, mock);
		recv.init(std::move(sock[1]), prng, 1, 2, 1 << 18, mock);

		send.mGenState->mDebug = cmd.isSet("debug");
		recv.mGenState->mDebug = cmd.isSet("debug");

		auto sReq = send.request<F4BitOtSend>(n);
		auto rReq = recv.request<F4BitOtRecv>(n);
		auto p0 = send.start() | macoro::make_eager();
		auto p1 = recv.start() | macoro::make_eager();


		u64 s = 0;
		while (s < n)
		{
			F4BitOtSend sot;
			F4BitOtRecv rot;

			auto r = macoro::sync_wait(macoro::when_all_ready(
				sReq.get(sot),
				rReq.get(rot)
			));

			std::get<0>(r).result();
			std::get<1>(r).result();

			for (u64 i = 0; i < sot.size() / 128; ++i)
			{
				auto exp =
					(sot.mOts[0][i] & (~rot.mChoiceMsb[i]) & (~rot.mChoiceLsb[i])) ^
					(sot.mOts[1][i] & (~rot.mChoiceMsb[i]) & (rot.mChoiceLsb[i])) ^
					(sot.mOts[2][i] & (rot.mChoiceMsb[i]) & (~rot.mChoiceLsb[i])) ^
					(sot.mOts[3][i] & (rot.mChoiceMsb[i]) & (rot.mChoiceLsb[i]));

				if (exp != rot.mOts[i])
					throw RTE_LOC;
				//if (i < 100)
				//    std::cout << " "<< rot.mChoice[i] << std::endl;
			}

			s += sot.size();
		}


		auto r = macoro::sync_wait(macoro::when_all_ready(
			std::move(p0), std::move(p1)
		));

		std::get<0>(r).result();
		std::get<1>(r).result();

	}

	//auto r = macoro::sync_wait(macoro::when_all_ready(
	//    std::move(t0),
	//    std::move(t1)
	//));

	//std::get<0>(r).result();
	//std::get<1>(r).result();
}

void CorGenerator_Ot_Test(const oc::CLP& cmd)
{

	u64 n = (1ull << 16) + 3234;

	for (auto mock : { false, true })
	{

		PRNG prng(oc::ZeroBlock);
		//SendBase sBase;sBase.resize(128);
		//RecvBase rBase;rBase.resize(128);
		//rBase.mChoice.randomize(prng);
		//for (u64 i = 0; i < 128; ++i)
		//{
		//    sBase.mBase[i][0] = prng.get<oc::block>();
		//    sBase.mBase[i][1] = prng.get<oc::block>();
		//    rBase.mBase[i] = sBase.mBase[i][rBase.mChoice[i]].getSeed();
		//}

		auto sock = coproto::LocalAsyncSocket::makePair();
		CorGenerator send;
		CorGenerator recv;
		send.init(std::move(sock[0]), prng, 0, 2, 1 << 18, mock);
		recv.init(std::move(sock[1]), prng, 1, 2, 1 << 18, mock);

		send.mGenState->mDebug = cmd.isSet("debug");
		recv.mGenState->mDebug = cmd.isSet("debug");

		auto sReq = send.sendOtRequest(n);
		auto rReq = recv.recvOtRequest(n);
		auto p0 = send.start() | macoro::make_eager();
		auto p1 = recv.start() | macoro::make_eager();


		u64 s = 0;
		while (s < n)
		{
			OtSend sot;
			OtRecv rot;

			auto r = macoro::sync_wait(macoro::when_all_ready(
				sReq.get(sot),
				rReq.get(rot)
			));

			std::get<0>(r).result();
			std::get<1>(r).result();

			for (u64 i = 0; i < sot.size(); ++i)
			{
				if (sot.mMsg[i][rot.mChoice[i]] != rot.mMsg[i])
					throw RTE_LOC;
				//if (i < 100)
				//    std::cout << " "<< rot.mChoice[i] << std::endl;
			}

			s += sot.size();
		}


		auto r = macoro::sync_wait(macoro::when_all_ready(
			std::move(p0), std::move(p1)
		));

		std::get<0>(r).result();
		std::get<1>(r).result();

	}

	//auto r = macoro::sync_wait(macoro::when_all_ready(
	//    std::move(t0),
	//    std::move(t1)
	//));

	//std::get<0>(r).result();
	//std::get<1>(r).result();
}

void CorGenerator_BinOle_Test(const oc::CLP& cmd)
{

	u64 n = cmd.getOr("n", (1ull << 16) + 3234);

	for (auto mock : { false, true })
	{


		PRNG prng(oc::ZeroBlock);
		//SendBase sBase;sBase.resize(128);
		//RecvBase rBase;rBase.resize(128);
		//rBase.mChoice.randomize(prng);
		//for (u64 i = 0; i < 128; ++i)
		//{
		//    sBase.mBase[i][0] = prng.get<oc::block>();
		//    sBase.mBase[i][1] = prng.get<oc::block>();
		//    rBase.mBase[i] = sBase.mBase[i][rBase.mChoice[i]].getSeed();
		//}

		auto sock = coproto::LocalAsyncSocket::makePair();
		CorGenerator  send;
		CorGenerator  recv;

		send.init(std::move(sock[0]), prng, 0, 1, 1 << 18, mock);
		recv.init(std::move(sock[1]), prng, 1, 1, 1 << 18, mock);
		send.mGenState->mDebug = cmd.isSet("debug");
		recv.mGenState->mDebug = cmd.isSet("debug");



		auto sReq = send.binOleRequest(n);
		auto rReq = recv.binOleRequest(n);
		auto p0 = send.start() | macoro::make_eager();
		auto p1 = recv.start() | macoro::make_eager();


		u64 s = 0;
		while (s < n)
		{
			BinOle sot;
			BinOle rot;

			auto r = macoro::sync_wait(macoro::when_all_ready(
				sReq.get(sot),
				rReq.get(rot)
			));

			std::get<0>(r).result();
			std::get<1>(r).result();

			for (u64 i = 0; i < sot.mMult.size(); ++i)
			{
				if ((sot.mMult[i] & rot.mMult[i]) != (sot.mAdd[i] ^ rot.mAdd[i]))
					throw RTE_LOC;
			}

			s += sot.size();
		}

		auto r = macoro::sync_wait(macoro::when_all_ready(
			std::move(p0), std::move(p1)
		));

		std::get<0>(r).result();
		std::get<1>(r).result();
	}
}


void CorGenerator_TritOt_Test(const oc::CLP& cmd)
{
	u64 n = (1ull << 16) + 3234;

	PRNG prng(oc::ZeroBlock);

	for (u64 i = 0; i < n; ++i)
	{
		std::array<block, 8> b;
		b = prng.get();
		u8 msb, lsb;
		sample8Mod3(b.data(), msb, lsb);

		if (msb & lsb)
			throw RTE_LOC;
	}

	for (auto mock : { false, true })
	{


		auto sock = coproto::LocalAsyncSocket::makePair();
		CorGenerator send;
		CorGenerator recv;
		send.init(std::move(sock[0]), prng, 0, 2, 1 << 18, mock);
		recv.init(std::move(sock[1]), prng, 1, 2, 1 << 18, mock);

		send.mGenState->mDebug = cmd.isSet("debug");
		recv.mGenState->mDebug = cmd.isSet("debug");

		auto sReq = send.request<TritOtSend>(n);
		auto rReq = recv.request<TritOtRecv>(n);
		auto p0 = send.start() | macoro::make_eager();
		auto p1 = recv.start() | macoro::make_eager();


		u64 s = 0;
		while (s < n)
		{
			TritOtSend sot;
			TritOtRecv rot;

			auto r = macoro::sync_wait(macoro::when_all_ready(
				sReq.get(sot),
				rReq.get(rot)
			));

			std::get<0>(r).result();
			std::get<1>(r).result();

			for (u64 i = 0; i < sot.size(); ++i)
			{
				std::array<int, 2> m =
				{
					bit(sot.lsb()[0].data(), i) + 2 * bit(sot.msb()[0].data(), i),
					bit(sot.lsb()[1].data(), i) + 2 * bit(sot.msb()[1].data(), i)
				};

				int mc = bit(rot.lsb().data(), i) + 2 * bit(rot.msb().data(), i);
				int c = bit(rot.choice().data(), i);
				if (m[c] != mc)
					throw RTE_LOC;

				if (m[0] > 2 || m[1] > 2)
					throw RTE_LOC;
			}

			s += sot.size();
		}


		auto r = macoro::sync_wait(macoro::when_all_ready(
			std::move(p0), std::move(p1)
		));

		std::get<0>(r).result();
		std::get<1>(r).result();

	}

	//auto r = macoro::sync_wait(macoro::when_all_ready(
	//    std::move(t0),
	//    std::move(t1)
	//));

	//std::get<0>(r).result();
	//std::get<1>(r).result();
}

void CorGenerator_mixed_Test(const oc::CLP& cmd)
{

	u64 n = (1ull << 11) + 3234;
	u64 reqSize = 1 << 10;
	for (auto mock : { false, true })
	{
		PRNG prng(oc::ZeroBlock);
		auto sock = coproto::LocalAsyncSocket::makePair();
		CorGenerator  ole[2];

		ole[0].init(std::move(sock[0]), prng, 0, 1, 1 << 18, mock);
		ole[1].init(std::move(sock[1]), prng, 1, 1, 1 << 18, mock);
		ole[0].mGenState->mDebug = cmd.isSet("debug");
		ole[1].mGenState->mDebug = cmd.isSet("debug");

		std::array<std::vector<OtSendRequest>, 2> otSends;
		std::array<std::vector<OtRecvRequest>, 2> otRecvs;
		std::array<std::vector<BinOleRequest>, 2> oles;

		for (u64 i = 0; i < n; i += reqSize)
		{
			oles[0].push_back(ole[0].binOleRequest(reqSize));
			oles[1].push_back(ole[1].binOleRequest(reqSize));

			otRecvs[0].push_back(ole[0].recvOtRequest(reqSize));
			otSends[1].push_back(ole[1].sendOtRequest(reqSize));

			otSends[0].push_back(ole[0].sendOtRequest(reqSize));
			otRecvs[1].push_back(ole[1].recvOtRequest(reqSize));
		}
		auto p0 = ole[0].start() | macoro::make_eager();
		auto p1 = ole[1].start() | macoro::make_eager();


		u64 s = 0;
		u64 rIdx = 0;
		while (s < n)
		{

			{
				BinOle sot;
				BinOle rot;

				//auto p0 = oles[0][rIdx].start() | macoro::make_eager();
				//auto p1 = oles[1][rIdx].start() | macoro::make_eager();
				for (u64 j = 0; j < reqSize;)
				{
					auto r = macoro::sync_wait(macoro::when_all_ready(
						oles[0][rIdx].get(rot),
						oles[1][rIdx].get(sot)
					));

					std::get<0>(r).result();
					std::get<1>(r).result();

					for (u64 i = 0; i < sot.mMult.size(); ++i)
					{
						if ((sot.mMult[i] & rot.mMult[i]) != (sot.mAdd[i] ^ rot.mAdd[i]))
							throw RTE_LOC;
					}

					j += sot.size();
				}

				//auto r = macoro::sync_wait(macoro::when_all_ready(
				//    std::move(p0), std::move(p1)
				//));

				//std::get<0>(r).result();
				//std::get<1>(r).result();
			}

			for (u64 p = 0; p < 2; ++p)
			{

				OtSend sot;
				OtRecv rot;

				//auto p0 = otRecvs[p ^ 0][rIdx].start() | macoro::make_eager();
				//auto p1 = otSends[p ^ 1][rIdx].start() | macoro::make_eager();

				for (u64 j = 0; j < reqSize; )
				{
					rot.mChoice = {};
					auto r = macoro::sync_wait(macoro::when_all_ready(
						otRecvs[p ^ 0][rIdx].get(rot),
						otSends[p ^ 1][rIdx].get(sot)
					));

					std::get<0>(r).result();
					std::get<1>(r).result();
					//std::cout << "--------------" << std::endl;
					u64 failed = 0;
					for (u64 i = 0; i < sot.mMsg.size(); ++i)
					{
						if (sot.mMsg[i][rot.mChoice[i]] != rot.mMsg[i])
						{
							std::cout << i << " " << sot.mMsg[i][0] << " " << sot.mMsg[i][1] << " != " << rot.mMsg[i] << " @ " << rot.mChoice[i] << std::endl;

							++failed;
							if (failed > 40)
								break;
						}
					}
					if (failed)
						throw RTE_LOC;

					j += sot.size();
				}

			}
			++rIdx;
			s += reqSize;
		}

		auto r = macoro::sync_wait(macoro::when_all_ready(
			std::move(p0), std::move(p1)
		));

		std::get<0>(r).result();
		std::get<1>(r).result();
		//auto r = macoro::sync_wait(macoro::when_all_ready(
		//    std::move(p0), std::move(p1)
		//));

		//std::get<0>(r).result();
		//std::get<1>(r).result();
	}
}

