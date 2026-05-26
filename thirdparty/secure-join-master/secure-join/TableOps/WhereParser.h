#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include "secure-join/Defines.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "cryptoTools/Common/BitVector.h"
#include "secure-join/Util/ArrGate.h"
#include "secure-join/Join/Table.h"

namespace secJoin
{

	enum class ArrGateType : oc::u8
	{
		EQUALS = 1,
		NOT_EQUALS = 2,
		AND = 3,
		OR = 4,
		ADDITION = 5,
		LESS_THAN = 6,
		GREATER_THAN_EQUALS = 7,
		XOR = 8,
	};


	struct ArrGate
	{
		ArrGateType mType;
		std::array<oc::u64, 2> mInput;
		oc::u64 mOutput;

		ArrGate(oc::u64 op, oc::u64 input1, oc::u64 input2, oc::u64 output)
		{
			assert(op < 8);
			mType = (ArrGateType)op;
			mInput[0] = input1;
			mInput[1] = input2;
			mOutput = output;
		}

		ArrGate(ArrGateType op, oc::u64 input1, oc::u64 input2, oc::u64 output)
		{
			mType = op;
			mInput[0] = input1;
			mInput[1] = input2;
			mOutput = output;
		}

		ArrGate() = default;

	};

    struct WhBundle
    {
        oc::BetaBundle mBundle;
        ColumnType mType;

        WhBundle(oc::BetaBundle& a, ColumnType c)
            : mBundle(a), mType(c) {}

		WhBundle(const ColumnInfo& col)
		{
			mBundle.resize(col.getBitCount());
			mType = col.mType;
		}

		WhBundle() = default;
		WhBundle(const WhBundle&) = default;
		WhBundle(WhBundle&&) = default;
		WhBundle&operator=(const WhBundle&) = default;
		WhBundle&operator=(WhBundle&&) = default;


		u64 bitCount() const
		{
			return mBundle.size();
		}

		// returns a possibly sign extended bundle of the underlying value.
		oc::BetaBundle getBundle(oc::BetaCircuit& cd, u64 size) const
		{
			oc::BetaBundle ret;ret.mWires.reserve(size);
			ret = mBundle;

			// sign extend
			if (mType == ColumnType::Int)
			{
				while (ret.size() < size)
					ret.push_back(ret.back());
			}
			else if (mType == ColumnType::Boolean || mType == ColumnType::String)
			{
				// zero extend
				while (ret.size() < size)
				{
					ret.mWires.emplace_back();
					cd.addConst(ret.back(), 0);
				}
			}
			return ret;
		}
    };

    struct WhereParser
    {
        oc::BetaCircuit parse(
            const std::vector<ColumnInfo>& columns,
            const std::vector<ArrGate>& gates,
			const std::vector<std::string> inputColumns,
			const std::vector<std::string>& literals,
            const std::vector<ColumnType>& literalTypes);
    };
}