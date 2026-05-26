#include "WhereParser.h"


namespace secJoin
{

	inline ArrGateType numToGateType(oc::u64 type)
	{
		if (type <= 8)
			return (ArrGateType)type;

		std::string temp = "Gate Type not available for num = " + std::to_string(type)
			+ "\n" + LOCATION;
		throw std::runtime_error(temp);
	}

	inline std::string gateToString(ArrGateType type)
	{
		if (type == ArrGateType::EQUALS)return "Equals";
		else if (type == ArrGateType::NOT_EQUALS)return "Not Equals";
		else if (type == ArrGateType::AND)return "And";
		else if (type == ArrGateType::OR)return "Or";
		else if (type == ArrGateType::XOR)return "Xor";
		else if (type == ArrGateType::ADDITION)return "Addition";
		else if (type == ArrGateType::LESS_THAN)return "Less Than";
		else if (type == ArrGateType::GREATER_THAN_EQUALS)return "Greater Than Equals";
		else
			throw RTE_LOC;
	}


	inline std::ostream& operator<<(std::ostream& o, ArrGate& gate)
	{
		o << gateToString(gate.mType) << " "
			<< gate.mInput[0] << " "
			<< gate.mInput[1] << " "
			<< gate.mOutput << std::endl;
		return o;
	}


	oc::BetaCircuit WhereParser::parse(
		const std::vector<ColumnInfo>& st,
		const std::vector<ArrGate>& gates,
		const std::vector<std::string> inputColumns,
		const std::vector<std::string>& literals,
		const std::vector<ColumnType>& literalTypes)
	{
		oc::BetaCircuit cd;


		std::vector<WhBundle> mWhBundle(inputColumns.size() + literals.size() + gates.size());// = parseInputs(inputs, inputTypes, st, cd);

		u64 idx = 0;
		for (u64 i = 0; i < inputColumns.size(); ++i, ++idx)
		{
			auto col = std::find_if(st.begin(), st.end(), [&](const auto& c) { return c.mName == inputColumns[i];});
			if (col == st.end())
				throw RTE_LOC;// failed to find column.
			mWhBundle[idx] = WhBundle(*col);
			cd.addInputBundle(mWhBundle[idx].mBundle);
		}

		// Adding Output Bundle 
		oc::BetaBundle outBundle(1);
		cd.addOutputBundle(outBundle);

		if (literals.size() != literalTypes.size())
			throw RTE_LOC;
		for (u64 i = 0; i < literals.size(); ++i, ++idx)
		{
			oc::BitVector val;;

			switch (literalTypes[i])
			{
			case ColumnType::Int:
			{
				i64 v = std::stoll(literals[i]);
				val.append((u8*)&v, 64);
				u64 msb = val.size();
				while (msb > 1 && val[msb - 1] == val.back())
					--msb;
				auto size = std::min<u64>(msb + 1, val.size());
				assert(val[size - 1] == val.back());
				val.resize(size);
				break;
			}
			case ColumnType::Boolean:
			{
				if (literals[i] == "1" || literals[i] == "true")
				{
					val.pushBack(1);
				}
				else if (literals[i] == "0" || literals[i] == "false")
				{
					val.pushBack(0);
				}
				else
					throw RTE_LOC;
				break;
			}
			case ColumnType::String:
			{
				val.append((u8*)literals[i].data(), literals[i].size() * 8);
				break;
			}
			case ColumnType::Bin:
			{
				std::vector<u8> data(oc::divCeil(literals[i].size(), 2));
				fromHex(literals[i], data);
				val.append(data.data(), data.size());
				break;
			}
			default:
				throw RTE_LOC;
			}

			//std::cout << literals[i] << " -> " << val << std::endl;
			mWhBundle[idx].mType = literalTypes[i];
			mWhBundle[idx].mBundle.resize(val.size());
			cd.addConstBundle(mWhBundle[idx].mBundle, val);

			//cd.addPrint("input " + std::to_string(idx) + " = Literal " + std::to_string(i) + " = ");
			//cd.addPrint(mWhBundle[idx].mBundle);
			//cd.addPrint("\n");
		}

		auto intPrint = [](const oc::BitVector& v) {
			i64 val = 0;
			osuCrypto::copyBytesMin(val, v);
			val = signExtend(val, v.size() - 1);
			return std::to_string(val);
			};

		auto strPrint = [](const oc::BitVector& v) {
			std::string s(v.sizeBytes(), 'a');
			osuCrypto::copyBytes(s, v);
			return s;
			};

		// Adding Inputbundles
		for (u64 i = 0; i < gates.size(); i++, ++idx)
		{
			if (gates[i].mInput[0] >= idx)
				throw RTE_LOC;
			if (gates[i].mInput[1] >= idx)
				throw RTE_LOC;
			if (gates[i].mOutput != idx)
				throw RTE_LOC;

			auto& a = mWhBundle[gates[i].mInput[0]];
			auto& b = mWhBundle[gates[i].mInput[1]];
			auto& c = mWhBundle[gates[i].mOutput];

			switch (gates[i].mType)
			{
			case ArrGateType::EQUALS:
			case ArrGateType::NOT_EQUALS:
			{

				auto size = std::max(a.bitCount(), b.bitCount());
				auto ab = a.getBundle(cd, size);
				auto bb = b.getBundle(cd, size);

				if (i == gates.size() - 1)
					c.mBundle = outBundle;
				else
				{
					c.mBundle.resize(1);
					c.mType = ColumnType::Boolean;
					cd.addTempWireBundle(c.mBundle);
				}
				
				oc::BetaLibrary::eq_build(cd, ab, bb, c.mBundle);
				if (gates[i].mType == ArrGateType::NOT_EQUALS)
					cd.addInvert(c.mBundle[0]);

				//cd.addPrint("a ");
				//cd.addPrint(ab);
				//cd.addPrint(" ");
				//cd.addPrint(ab, intPrint);
				//cd.addPrint("\nb ");
				//cd.addPrint(bb);
				//cd.addPrint(" ");
				//cd.addPrint(bb, intPrint);
				//cd.addPrint("\nc ");
				//cd.addPrint(c.mBundle);
				//cd.addPrint("\n");

				break;
			}
			case ArrGateType::AND:
			case ArrGateType::OR:
			case ArrGateType::XOR:
			{
				if (a.bitCount() != 1)
					throw RTE_LOC;
				if (b.bitCount() != 1)
					throw RTE_LOC;

				if (i == gates.size() - 1)
					c.mBundle = outBundle;
				else
				{
					c.mBundle.resize(1);
					c.mType = ColumnType::Boolean;
					cd.addTempWireBundle(c.mBundle);
				}

				if (gates[i].mType == ArrGateType::AND)
					oc::BetaLibrary::bitwiseAnd_build(cd, a.mBundle, b.mBundle, c.mBundle);
				else if (gates[i].mType == ArrGateType::OR)
				{
					oc::BetaLibrary::bitwiseOr_build(cd, a.mBundle, b.mBundle, c.mBundle);
				}
				else if (gates[i].mType == ArrGateType::XOR)
				{
					oc::BetaLibrary::bitwiseXor_build(cd, a.mBundle, b.mBundle, c.mBundle);
				}
				else
					throw RTE_LOC;


				//cd.addPrint("a ");
				//cd.addPrint(a.mBundle);
				//cd.addPrint(" " + gateToString(gates[i].mType) + " b ");
				//cd.addPrint(b.mBundle);
				//cd.addPrint(" = c ");
				//cd.addPrint(c.mBundle);
				//cd.addPrint("\n");

				break;
			}
			case ArrGateType::ADDITION:
			{

				auto size = std::max(a.bitCount(), b.bitCount());
				auto ab = a.getBundle(cd, size);
				auto bb = b.getBundle(cd, size);

				// addition can't be the output gate. must be boolean.
				if (i == gates.size() - 1)
					throw RTE_LOC;

				c.mBundle.resize(size);
				c.mType = ColumnType::Int;
				cd.addTempWireBundle(c.mBundle);
				oc::BetaBundle temp(size);
				cd.addTempWireBundle(temp);

				oc::BetaLibrary::add_build(cd, ab, bb, c.mBundle, temp, oc::BetaLibrary::IntType::TwosComplement, oc::BetaLibrary::Optimized::Depth);
				break;
			}
			case ArrGateType::LESS_THAN:
			case ArrGateType::GREATER_THAN_EQUALS:
			{
				if (a.mType != ColumnType::Int &&
					b.mType != ColumnType::Int)
					throw RTE_LOC;

				auto size = std::max(a.bitCount(), b.bitCount());
				auto ab = a.getBundle(cd, size);
				auto bb = b.getBundle(cd, size);


				if (i == gates.size() - 1)
					c.mBundle = outBundle;
				else
				{
					c.mBundle.resize(1);
					c.mType = ColumnType::Boolean;
					cd.addTempWireBundle(c.mBundle);
				}

				auto it = oc::BetaLibrary::IntType::TwosComplement;

				if (gates[i].mType == ArrGateType::LESS_THAN)
					oc::BetaLibrary::lessThan_build(cd, ab, bb, c.mBundle, it, oc::BetaLibrary::Optimized::Depth);
				else if (gates[i].mType == ArrGateType::GREATER_THAN_EQUALS)
					oc::BetaLibrary::greaterThanEq_build(cd, ab, bb, c.mBundle, it, oc::BetaLibrary::Optimized::Depth);
				else
					throw RTE_LOC;


				//cd.addPrint("a ");
				//cd.addPrint(ab);
				//cd.addPrint(" ");
				//cd.addPrint(ab, intPrint);
				//cd.addPrint(" < b ");
				//cd.addPrint(bb);
				//cd.addPrint(" ");
				//cd.addPrint(bb, intPrint);
				//cd.addPrint(" = c ");
				//cd.addPrint(c.mBundle);
				//cd.addPrint("\n");

				break;
			}
			default:
				throw RTE_LOC;
				break;
			}
		}
		return cd;
	}
}