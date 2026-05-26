#include "Where_Test.h"

#include "cryptoTools/Common/BitVector.h"
// #include <cstdlib>
#include "secure-join/config.h"
#include "secure-join/TableOps/Where.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Util/Util.h"
#include "secure-join/TableOps/GroupBy.h"
#include "secure-join/TableOps/WhereParser.h"


using namespace secJoin;
#include "cryptoTools/Common/TestCollection.h"


void where_cir_test(const oc::CLP& cmd)
{
	u64 n = cmd.getOr("n", 20);

	Table table(n, {
		{"idx", ColumnType::Int, 16},
		{"str", ColumnType::String, 8 * 32}
		});

	oc::BetaCircuit cir;
	{
		oc::BetaBundle idx(table["idx"].mCol.getBitCount());
		oc::BetaBundle str(table["str"].mCol.getBitCount());
		oc::BetaBundle out(1);
		cir.addInputBundle(idx);
		cir.addInputBundle(str);
		cir.addOutputBundle(out);

		oc::BetaBundle idxXor(1);
		cir.addTempWireBundle(idxXor);
		cir.addGate(idx[0], idx[1], oc::GateType::Xor, idxXor[0]);

		//      cir.addPrint("idx = ");
		//      cir.addPrint(idx, [](const oc::BitVector& bv) {
			  //	return std::to_string(bv.getSpan<u16>()[0]);
		//          });
			  //cir.addPrint("\nstr = ");
			  //cir.addPrint(str, [](const oc::BitVector& bv) {
		//          return std::string((char*)bv.data(), bv.sizeBytes());
		//      });
			  //cir.addPrint("\n");

			  //cir.addPrint("idxXor = ");
			  //cir.addPrint(idxXor);
			  //cir.addPrint("\n");

		oc::BetaBundle helloWorld(table["str"].mCol.getBitCount()), eqHelloWorld(1);
		cir.addTempWireBundle(eqHelloWorld);
		std::string hw("hello world");
		oc::BitVector hwv((u8*)hw.data(), hw.size() * 8);
		hwv.resize(helloWorld.size());
		cir.addConstBundle(helloWorld, hwv);
		oc::BetaLibrary::eq_build(cir, helloWorld, str, eqHelloWorld);

		oc::BetaBundle goodbye(table["str"].mCol.getBitCount()), eqGoodbye(1);
		cir.addTempWireBundle(eqGoodbye);
		std::string gw("goodbye world");
		oc::BitVector gwv((u8*)gw.data(), gw.size() * 8);
		gwv.resize(goodbye.size());
		cir.addConstBundle(goodbye, gwv);
		oc::BetaLibrary::eq_build(cir, goodbye, str, eqGoodbye);

		oc::BetaBundle eq(1);
		cir.addTempWireBundle(eq);
		cir.addGate(eqGoodbye[0], eqHelloWorld[0], oc::GateType::Or, eq[0]);

		//cir.addPrint("eqHelloWorld = ");
		//cir.addPrint(eqHelloWorld);
		//cir.addPrint("\neqGoodbye = ");
		//cir.addPrint(eqGoodbye);
		//cir.addPrint("\n");


		//cir.addPrint("eq = ");
		//cir.addPrint(eq);
		//cir.addPrint("\n");


		cir.addGate(eq[0], idxXor[0], oc::GateType::And, out[0]);
	}
	auto c2 = Where::makeWhereClause(cir);

	PRNG prng(block(324, 234));

	table.mIsActive.resize(n);
	std::vector<u8> exp(n);
	for (u64 i = 0; i < n; ++i)
	{
		table.mIsActive[i] = 1;//prng.getBit();
		osuCrypto::copyBytesMin(table.mColumns[0].mData.mData[i], i);

		if ((i % 3) == 0)
			osuCrypto::copyBytesMin(table.mColumns[1].mData.mData[i], std::string("hello world"));
		else if ((i % 3) == 1)
			osuCrypto::copyBytesMin(table.mColumns[1].mData.mData[i], std::string("goodbye world"));
		else
			osuCrypto::copyBytesMin(table.mColumns[1].mData.mData[i], std::string("what world"));

		bool w = (i % 3 < 2) && (((i ^ (i >> 1)) & 1));
		exp[i] = (table.mIsActive[i] == 1) && w;

		std::vector<oc::BitVector> inputs(table.mColumns.size()), output(1);
		for (u64 j = 0; j < table.mColumns.size(); ++j)
			inputs[j].append((u8*)table[j].mCol.mData[i].data(), table[j].mCol.getBitCount());
		output[0].resize(1);

		cir.evaluate(inputs, output);

		if (bool(output[0][0]) != w)
			throw RTE_LOC;

		inputs.push_back(oc::BitVector());
		inputs.back().append((u8*)&table.mIsActive[i], 1);
		c2.evaluate(inputs, output);


		if (output[0][0] != exp[i])
			throw RTE_LOC;
	}


	auto shares = table.share(prng);

	std::array<Where, 2> wheres;
	std::array<CorGenerator, 2> gen;
	std::vector<u64> inputs{ 0, 1 };


	auto sock = coproto::LocalAsyncSocket::makePair();
	std::array<std::vector<ColumnInfo>, 2> cols{
		shares[0].getColumnInfo(),
		shares[1].getColumnInfo()
	};
	gen[0].init(sock[0].fork(), prng, 0, 1, 1 << 16, true);
	gen[1].init(sock[1].fork(), prng, 1, 1, 1 << 16, true);
	wheres[0].init(n, cols[0], inputs, cir, gen[0]);
	wheres[1].init(n, cols[1], inputs, cir, gen[1]);

	std::array<PRNG, 2> prngs{ block(3243,2342),block(453245,3245) };

	macoro::sync_wait(macoro::when_all_ready(
		wheres[0].where(shares[0], shares[0], sock[0], prngs[0]),
		wheres[1].where(shares[1], shares[1], sock[1], prngs[1]),
		gen[0].start(),
		gen[1].start()
	));

	auto act = reveal(shares[0], shares[1], false);
	if (exp != act.mIsActive)
	{
		for (u64 i = 0; i < n; ++i)
		{
			auto cc = shares[0].mIsActive[i] ^ shares[1].mIsActive[i];
			std::cout << i << ": e " << int(exp[i]) << " a " << int(act.mIsActive[i]) << " " << cc << std::endl;
		}
		throw RTE_LOC;
	}
}

void evalWhGate(
	Table& T,
	const std::vector<ArrGate>& gates,
	const std::vector<std::string>& literals,
	const std::vector<std::string>& literalsType,
	const std::unordered_map<u64, u64>& map,
	const bool printSteps,
	const bool mock)
{
	auto sock = coproto::LocalAsyncSocket::makePair();

	PRNG prng0(oc::ZeroBlock);
	PRNG prng1(oc::OneBlock);

	std::array<Table, 2> Ts;
	T.share(Ts, prng0);

	u64 totalCol = T.cols();

	for (auto remDummies : { false, true })
	{
		CorGenerator ole0, ole1;
		ole0.init(sock[0].fork(), prng0, 0, 1, 1 << 16, mock);
		ole1.init(sock[1].fork(), prng1, 1, 1, 1 << 16, mock);

		Where wh0, wh1;
		SharedTable out0, out1;

		wh0.mInsecurePrint = printSteps;
		wh1.mInsecurePrint = printSteps;

		throw RTE_LOC;
		//wh0.init(Ts[0], gates, literals, literalsType, totalCol, map, ole0, remDummies);
		//wh1.init(Ts[1], gates, literals, literalsType, totalCol, map, ole1, remDummies);

		//wh0.mRemoveInactive.mCachePerm = remDummies;
		//wh1.mRemoveInactive.mCachePerm = remDummies;

		auto r = macoro::sync_wait(macoro::when_all_ready(
			ole0.start(),
			ole1.start(),
			wh0.where(Ts[0], out0, sock[0], prng0),
			wh1.where(Ts[1], out1, sock[1], prng1)
		));

		std::get<0>(r).result();
		std::get<1>(r).result();
		std::get<2>(r).result();
		std::get<3>(r).result();

		auto act = reveal(out0, out1, false);

		throw RTE_LOC;
		//Perm pi;
		//if (remDummies)
		//{
		//    ComposedPerm p0 = wh0.mRemoveInactive.mPermutation;
		//    ComposedPerm p1 = wh1.mRemoveInactive.mPermutation;
		//    pi = p1.permShare().compose(p0.permShare());
		//}

		//Table exp = where(T, gates, literals, literalsType, totalCol, map, printSteps);

		//if (exp != act)
		//{
		//    std::cout << "remove dummies flag = " << remDummies << std::endl;
		//    std::cout << "exp \n" << exp << std::endl;
		//    std::cout << "act \n" << act << std::endl;
		//    throw RTE_LOC;
		//}

	}
}


void WhereParser_genWhBundle_Test(const oc::CLP& cmd)
{/*
	u64 nT = cmd.getOr("T", 511);
	bool printSteps = cmd.isSet("print");
	Table T;

	T.init(nT, { {
		{"T1", ColumnType::Int, 8},
		{"T2", ColumnType::Int, 16},
		{"T3", ColumnType::String, 16},
	} });
	u64 totalCol = T.cols();

	std::vector<std::string> literals = { "T1", "T2", "T3", "TestString", "10" };
	std::vector<std::string> literalsType = { WHBUNDLE_COL_TYPE, WHBUNDLE_COL_TYPE,
		WHBUNDLE_COL_TYPE, WHBUNDLE_STRING_TYPE, WHBUNDLE_NUM_TYPE };

	std::unordered_map<u64, u64> map;
	for (oc::u64 i = 0; i < totalCol; i++)
		map[i] = i;

	Where wh;
	wh.mInsecurePrint = printSteps;
	throw RTE_LOC;*/
	//wh.genWhBundle(literals, literalsType, totalCol, T, map);

	//for (u64 i = 0; i < wh.mWhBundle.size(); i++)
	//{
	//    if (wh.mWhBundle[i].mType == WhType::Col)
	//    {
	//        if (i >= totalCol)
	//            throw RTE_LOC;
	//        u64 size = wh.getInputColSize(T, i, totalCol, map);
	//        if (wh.mWhBundle[i].mBundle.size() != size)
	//            throw RTE_LOC;
	//    }
	//    else if (wh.mWhBundle[i].mType == WhType::Number)
	//    {
	//        BitVector bitVector = wh.mWhBundle[i].mVal;
	//        oc::u64 exp = 0;
	//        osuCrypto::copyBytesMin(exp, bitVector);
	//        oc::u64 act = stoll(literals[i]);

	//        if (act != exp)
	//            throw RTE_LOC;
	//    }
	//    else if (wh.mWhBundle[i].mType == WhType::String)
	//    {
	//        BitVector bitVector = wh.mWhBundle[i].mVal;
	//        std::string exp;
	//        exp.resize(bitVector.size() / 8);
	//        //m emcpy(exp.data(), bitVector.data(), bitVector.size() / 8);
	//        osuCrypto::copyBytes(exp, bitVector);

	//        std::string act = literals[i];
	//        if (act.compare(exp) != 0)
	//            throw RTE_LOC;
	//    }
	//    else
	//        throw RTE_LOC;
	//}
}

void WhereParser_IntOps_Test(const oc::CLP& cmd)
{
	u64 n = 10;
	WhereParser parser;
	auto cols = std::vector<ColumnInfo>{
			{"int0", ColumnType::Int, 16},
			{"int1", ColumnType::Int, 8}
	};

	// 2, 3
	std::vector<std::string> literals = { "-64", " 64" };
	std::vector<ColumnType> literalTypes = { ColumnType::Int, ColumnType::Int };
	std::vector<std::string> inputCols{
		cols[0].mName,
		cols[1].mName,
	};

	PRNG prng(block(4353245, 3452345));
	u64 totalInputs = cols.size() + literals.size();
	std::vector<i64> inputs(totalInputs), bc(totalInputs);
	for (u64 i = cols.size(), j = 0ull; i < inputs.size(); ++i, ++j)
		inputs[i] = std::stoll(literals[j]);;

	for (auto op : {
		ArrGateType::EQUALS,
		ArrGateType::GREATER_THAN_EQUALS,
		ArrGateType::LESS_THAN,
		ArrGateType::NOT_EQUALS
		})
	{
		for (u64 in0 = 0; in0 < totalInputs; ++in0)
		{
			for (u64 in1 = 0; in1 < totalInputs; ++in1)
			{
				if (in0 == in1)
					continue;

				ArrGate gate(op, in0, in1, totalInputs);
				std::vector<ArrGate> gates{ gate };
				auto cir = parser.parse(cols, gates, inputCols, literals, literalTypes);

				std::vector<oc::BitVector> cirIn(cols.size()), cirOut(1);
				cirOut[0].resize(1);
				for (u64 i = 10; i < n; ++i)
				{
					for (u64 k = 0; k < cols.size(); ++k)
					{

						if (i == 0 && k == 0)
							inputs[0] = -64;
						else
							inputs[k] = PRNG(block(i, i)).get();
						inputs[k] = signExtend(inputs[k], cols[k].getBitCount() - 1);
						cirIn[k].resize(0);
						cirIn[k].append((u8*)&inputs[k], cols[k].getBitCount());
					}

					bool exp = false;
					switch (op)
					{
					case secJoin::ArrGateType::EQUALS:
						exp = (inputs[in0] == inputs[in1]);
						break;
					case secJoin::ArrGateType::NOT_EQUALS:
						exp = (inputs[in0] != inputs[in1]);
						break;
					case secJoin::ArrGateType::LESS_THAN:
						exp = (inputs[in0] < inputs[in1]);
						break;
					case secJoin::ArrGateType::GREATER_THAN_EQUALS:
						exp = (inputs[in0] >= inputs[in1]);
						break;
					default:
						throw RTE_LOC;
						break;
					}

					//for (u64 k = 0; k < inputs.size(); ++k)
					//{
					//	std::cout << "input[" << k << "] = " << inputs[k];
					//	if (k < cirIn.size())
					//		std::cout << " " << cirIn[k];
					//	std::cout << std::endl;
					//}

					cir.evaluate(cirIn, cirOut);
					if (bool(cirOut[0][0]) != exp)
						throw RTE_LOC;
				}
			}
		}
	}
}


void WhereParser_IntAdd_Test(const oc::CLP& cmd)
{
	u64 n = 10;
	WhereParser parser;
	auto cols = std::vector<ColumnInfo>{
			{"int0", ColumnType::Int, 16},
			{"int1", ColumnType::Int, 8}
	};

	// 2, 3
	std::vector<std::string> literals = { "-64", " 64" };
	std::vector<ColumnType> literalTypes = { ColumnType::Int, ColumnType::Int };
	std::vector<std::string> inputCols{
		cols[0].mName,
		cols[1].mName,
	};

	PRNG prng(block(4353245, 3452345));
	u64 totalInputs = cols.size() + literals.size();
	std::vector<i64> inputs(totalInputs), bc(totalInputs);
	for (u64 i = cols.size(), j = 0ull; i < inputs.size(); ++i, ++j)
	{
		inputs[i] = std::stoll(literals[j]);;
	}
	bc[0] = cols[0].getBitCount();
	bc[1] = cols[1].getBitCount();
	bc[2] = 8;
	bc[2] = 8;

	for (u64 in0 = 0; in0 < totalInputs; ++in0)
	{
		for (u64 in1 = 0; in1 < totalInputs; ++in1)
		{
			if (in0 == in1)
				continue;

			ArrGate gate0(ArrGateType::ADDITION, in0, in1, totalInputs);
			ArrGate gate1(ArrGateType::GREATER_THAN_EQUALS, totalInputs, in1, totalInputs + 1);
			std::vector<ArrGate> gates{ gate0, gate1 };
			auto cir = parser.parse(cols, gates, inputCols, literals, literalTypes);

			std::vector<oc::BitVector> cirIn(cols.size()), cirOut(1);
			cirOut[0].resize(1);
			for (u64 i = 10; i < n; ++i)
			{
				for (u64 k = 0; k < cols.size(); ++k)
				{

					if (i == 0 && k == 0)
						inputs[0] = -64;
					else
						inputs[k] = PRNG(block(i, i)).get();
					inputs[k] = signExtend(inputs[k], cols[k].getBitCount() - 1);
					cirIn[k].resize(0);
					cirIn[k].append((u8*)&inputs[k], cols[k].getBitCount());
				}

				auto val = signExtend(inputs[in0] + inputs[in1], std::max(bc[in0], bc[in1]) - 1);
				auto exp = (val >= inputs[in1]);
				//for (u64 k = 0; k < inputs.size(); ++k)
				//{
				//	std::cout << "input[" << k << "] = " << inputs[k];
				//	if (k < cirIn.size())
				//		std::cout << " " << cirIn[k];
				//	std::cout << std::endl;
				//}

				cir.evaluate(cirIn, cirOut);

				if (bool(cirOut[0][0]) != exp)
					throw RTE_LOC;

			}
		}
	}
}


std::string trim(const std::string& s)
{
	auto r = s;
	while (r.size() && r.back() == 0)
		r.pop_back();
	return r;
}

void WhereParser_StringOps_Test(const oc::CLP& cmd)
{
	u64 n = 10;
	WhereParser parser;
	auto cols = std::vector<ColumnInfo>{
		{"int0", ColumnType::String, 8 * 16},
		{"int1", ColumnType::String, 8 * 15}
	};

	// 2, 3
	std::vector<std::string> literals = { "hello world", "goodbye world" };
	std::vector<ColumnType> literalTypes = { ColumnType::String, ColumnType::String };
	std::vector<std::string> inputCols{
		cols[0].mName,
		cols[1].mName,
	};

	PRNG prng(block(4353245, 3452345));
	u64 totalInputs = cols.size() + literals.size();
	std::vector<std::string> inputs(totalInputs);
	for (u64 i = cols.size(), j = 0ull; i < inputs.size(); ++i, ++j)
		inputs[i] = literals[j];

	for (auto op : {
		ArrGateType::EQUALS,
		//ArrGateType::GREATER_THAN_EQUALS,
		//ArrGateType::LESS_THAN,
		ArrGateType::NOT_EQUALS })
	{
		for (u64 in0 = 0; in0 < totalInputs; ++in0)
		{
			for (u64 in1 = 0; in1 < totalInputs; ++in1)
			{
				if (in0 == in1)
					continue;

				ArrGate gate(op, in0, in1, totalInputs);
				std::vector<ArrGate> gates{ gate };
				auto cir = parser.parse(cols, gates, inputCols, literals, literalTypes);

				std::vector<oc::BitVector> cirIn(cols.size()), cirOut(1);
				cirOut[0].resize(1);
				for (u64 i = 0; i < n; ++i)
				{
					for (u64 k = 0; k < cols.size(); ++k)
					{
						if (i == 0 && k == 0) {
							inputs[0] = "hello world";
							while (inputs[0].size() != cols[0].getByteCount())
								inputs[0].push_back(0);
						}
						else
						{
							inputs[k].resize(cols[k].getByteCount());
							for (u64 l = 0; l < inputs[k].size(); ++l)
								inputs[k][l] = 'a' + (prng.get<u8>() % 26);
						}
						cirIn[k].resize(0);
						cirIn[k].append((u8*)inputs[k].data(), cols[k].getBitCount());
					}



					bool exp = false;
					switch (op)
					{
					case secJoin::ArrGateType::EQUALS:
						exp = (trim(inputs[in0]) == trim(inputs[in1]));
						break;
					case secJoin::ArrGateType::NOT_EQUALS:
						exp = (trim(inputs[in0]) != trim(inputs[in1]));
						break;
						//case secJoin::ArrGateType::LESS_THAN:
						//	exp = (inputs[in0] < inputs[in1]);
						//	break;
						//case secJoin::ArrGateType::GREATER_THAN_EQUALS:
						//	exp = (inputs[in0] >= inputs[in1]);
						//	break;
					default:
						throw RTE_LOC;
						break;
					}

					//for (u64 k = 0; k < inputs.size(); ++k)
					//{
					//	std::cout << "input[" << k << "] = " << inputs[k];
					//	if (k < cirIn.size())
					//		std::cout << " " << cirIn[k];
					//	std::cout << std::endl;
					//}

					cir.evaluate(cirIn, cirOut);
					if (bool(cirOut[0][0]) != exp)
						throw RTE_LOC;
				}
			}
		}
	}
}

void WhereParser_BoolOps_Test(const oc::CLP& cmd)
{
	WhereParser parser;
	auto cols = std::vector<ColumnInfo>{
		{"b0", ColumnType::Boolean, 1},
		{"b1", ColumnType::Boolean, 1}
	};

	// 2, 3
	std::vector<std::string> literals = { "0", "1", "false", "true" };
	std::vector<ColumnType> literalTypes = { ColumnType::Boolean, ColumnType::Boolean,ColumnType::Boolean, ColumnType::Boolean };
	std::vector<std::string> inputCols{
		cols[0].mName,
		cols[1].mName,
	};

	PRNG prng(block(4353245, 3452345));
	u64 totalInputs = cols.size() + literals.size();
	std::vector<bool> inputs(totalInputs);
	for (u64 i = cols.size(), j = 0ull; i < inputs.size(); ++i, ++j)
		inputs[i] = i & 1;//literals[j];

	for (auto op : {
		ArrGateType::EQUALS,
		ArrGateType::AND,
		ArrGateType::OR,
		ArrGateType::NOT_EQUALS })
	{
		for (u64 in0 = 0; in0 < totalInputs; ++in0)
		{
			for (u64 in1 = 0; in1 < totalInputs; ++in1)
			{
				if (in0 == in1)
					continue;

				ArrGate gate(op, in0, in1, totalInputs);
				std::vector<ArrGate> gates{ gate };
				auto cir = parser.parse(cols, gates, inputCols, literals, literalTypes);

				std::vector<oc::BitVector> cirIn(cols.size()), cirOut(1);
				cirOut[0].resize(1);
				cirIn[0].resize(1);
				cirIn[1].resize(1);
				for (u64 i = 0; i < 4; ++i)
				{
					inputs[0] = i & 1;
					inputs[1] = (i >> 1) & 1;
					cirIn[0][0] = inputs[0];
					cirIn[1][0] = inputs[1];

					bool exp = false;
					switch (op)
					{
					case secJoin::ArrGateType::EQUALS:
						exp = (inputs[in0] == inputs[in1]);
						break;
					case secJoin::ArrGateType::NOT_EQUALS:
						exp = (inputs[in0] != inputs[in1]);
						break;
					case secJoin::ArrGateType::AND:
						exp = (inputs[in0] && inputs[in1]);
						break;
					case secJoin::ArrGateType::OR:
						exp = (inputs[in0] || inputs[in1]);
						break;
					default:
						throw RTE_LOC;
						break;
					}

					//for (u64 k = 0; k < inputs.size(); ++k)
					//{
					//	std::cout << "input[" << k << "] = " << inputs[k];
					//	if (k < cirIn.size())
					//		std::cout << " " << cirIn[k];
					//	std::cout << std::endl;
					//}

					cir.evaluate(cirIn, cirOut);
					if (bool(cirOut[0][0]) != exp)
						throw RTE_LOC;
				}
			}
		}
	}
}


void WhereParser_Big_Test(const oc::CLP& cmd)
{
	u64 n = 100;
	WhereParser parser;
	auto cols = std::vector<ColumnInfo>{
		{"b0", ColumnType::Boolean, 1},
		{"b1", ColumnType::Boolean, 1},
		{"int0", ColumnType::Int, 32},
		{"int1", ColumnType::Int, 32},
		{"str0", ColumnType::String, 128},
		{"str1", ColumnType::String, 128},
		{"Bin0", ColumnType::Bin, 8},
		{"Bin1", ColumnType::Bin, 8}
	};

	// 2, 3
	std::vector<std::string> literals = { };//"0", "1", "false", "true"
	std::vector<ColumnType> literalTypes = { };//ColumnType::Boolean, ColumnType::Boolean, ColumnType::Boolean, ColumnType::Boolean };
	std::vector<std::string> inputCols{
		cols[0].mName,
		cols[1].mName,
		cols[2].mName,
		cols[3].mName,
		cols[4].mName,
		cols[5].mName,
		cols[6].mName,
		cols[7].mName
	};

	PRNG prng(block(4353245, 3452345));
	u64 totalInputs = cols.size() + literals.size();

	u64 outIdx = totalInputs, inIdx = totalInputs;
	std::vector<ArrGate> gates;
	gates.emplace_back(ArrGateType::AND, 0, 1, outIdx++);
	gates.emplace_back(ArrGateType::LESS_THAN, 2, 3, outIdx++);
	gates.emplace_back(ArrGateType::EQUALS, 4, 5, outIdx++);
	gates.emplace_back(ArrGateType::EQUALS, 6, 7, outIdx++);
	gates.emplace_back(ArrGateType::XOR, inIdx, inIdx + 1, outIdx++); inIdx += 2;
	gates.emplace_back(ArrGateType::XOR, inIdx, inIdx + 1, outIdx++); inIdx += 2;
	gates.emplace_back(ArrGateType::XOR, inIdx, inIdx + 1, outIdx++); inIdx += 2;

	auto cir = parser.parse(cols, gates, inputCols, literals, literalTypes);

	std::vector<oc::BitVector> cirIn(cols.size()), cirOut(1);
	cirOut[0].resize(1);
	for (u64 i = 0; i < n; ++i)
	{
		// bits
		bool b0 = prng.getBit();
		bool b1 = prng.getBit();
		cirIn[0].resize(0);
		cirIn[1].resize(0);
		cirIn[0].pushBack(b0);
		cirIn[1].pushBack(b1);
		auto r0 = b0 && b1;

		// ints
		i64 int0 = prng.get();
		i64 int1 = prng.get();
		int0 = signExtend(int0, cols[2].getBitCount() - 1);
		int1 = signExtend(int1, cols[3].getBitCount() - 1);
		cirIn[2].resize(0);
		cirIn[3].resize(0);
		cirIn[2].append((u8*)&int0, cols[2].getBitCount());
		cirIn[3].append((u8*)&int1, cols[3].getBitCount());
		auto r1 = int0 < int1;

		// string
		std::string str0, str1;
		str0.resize(cols[4].getByteCount());
		str1.resize(cols[5].getByteCount());
		for (u64 l = 0; l < 1; ++l)
			str0[l] = 'a' + (prng.get<u8>() % 26);
		for (u64 l = 0; l < 1; ++l)
			str1[l] = 'a' + (prng.get<u8>() % 26);
		cirIn[4].resize(0);
		cirIn[5].resize(0);
		cirIn[4].append((u8*)str0.data(), cols[4].getBitCount());
		cirIn[5].append((u8*)str1.data(), cols[5].getBitCount());
		auto r2 = str0 == str1;

		// bin
		std::vector<u8> bin0(cols[6].getByteCount());
		std::vector<u8> bin1(cols[7].getByteCount());
		bin0[0] = 'a' + prng.get<u8>() % 10;
		bin1[0] = 'a' + prng.get<u8>() % 10;
		cirIn[6].resize(0);
		cirIn[7].resize(0);
		cirIn[6].append(bin0.data(), cols[6].getBitCount());
		cirIn[7].append(bin1.data(), cols[7].getBitCount());
		auto r3 = bin0 == bin1;


		bool exp = r0 ^ r1 ^ r2^ r3;
		cir.evaluate(cirIn, cirOut);
		//for (u64 k = 0; k < inputs.size(); ++k)
		//{
		//	std::cout << "input[" << k << "] = " << inputs[k];
		//	if (k < cirIn.size())
		//		std::cout << " " << cirIn[k];
		//	std::cout << std::endl;
		//}

		if (bool(cirOut[0][0]) != exp)
			throw RTE_LOC;
	}
}

