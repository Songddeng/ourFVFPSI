#include "Where.h"
#include "secure-join/GMW/Circuit.h"

namespace secJoin {

	// given cir, we add an additional input which is the isActive flag.
	// the final output is the output of cir & isActive.
	oc::BetaCircuit Where::makeWhereClause(const oc::BetaCircuit& cir)
	{
		if (cir.mOutputs.size() != 1)
			throw std::runtime_error(LOCATION);

		oc::BetaCircuit whereClause;
		std::vector<BetaBundle> inputs(cir.mInputs.size());
		for (u64 i = 0; i < cir.mInputs.size(); i++)
		{
			inputs[i].resize(cir.mInputs[i].size());
			whereClause.addInputBundle(inputs[i]);
		}

		BetaBundle isActive(1);
		whereClause.addInputBundle(isActive);

		BetaBundle output(1);	
		whereClause.addOutputBundle(output);

		BetaBundle temp(1);
		whereClause.addTempWireBundle(temp);

		// add { temp = cir(inputs) } to `whereClause`.
		evaluate(whereClause, cir, inputs, { &temp, 1 });

		// add { output = temp & isActive } to `whereClause`.
		whereClause.addGate(temp.mWires[0], isActive.mWires[0], oc::GateType::And, output.mWires[0]);

		return whereClause;
	}

	void Where::init(
		u64 rows,
		span<ColumnInfo> columns,
		span<u64> whereInputs,
		oc::BetaCircuit& cir,
		CorGenerator& ole,
		bool remDummiesFlag)
	{
		if (cir.mInputs.size() != whereInputs.size())
			throw std::runtime_error(LOCATION);	
		if (cir.mOutputs.size() != 1)
			throw std::runtime_error(LOCATION);
		for (auto i : oc::rng(whereInputs.size()))
		{
			if (whereInputs[i] >= columns.size())
				throw std::runtime_error(LOCATION);
			if (columns[whereInputs[i]].mBitCount != cir.mInputs[i].size())
				throw std::runtime_error(LOCATION);
		}

		mRows = rows;
		mWhereInputs = std::vector<u64>(whereInputs.begin(), whereInputs.end());
		mWhereClauseCir = makeWhereClause(cir);
		mGmw.init(rows, mWhereClauseCir, ole);
		for (auto i : oc::rng(whereInputs.size()))
			mColumns.push_back(columns[whereInputs[i]]);

		if (remDummiesFlag)
		{
			u64 bytesPerRow = 1; // is active flag
			for (u64 i = 0; i < whereInputs.size(); i++)
				bytesPerRow += columns[i].getByteCount();
			mRemoveInactive.emplace(rows, bytesPerRow, ole);
		}
	}

	macoro::task<> Where::where(
		const Table& input,
		Table& output,
		coproto::Socket& sock,
		PRNG& prng)
	{
		if (input.mColumns.size() != mColumns.size())
			throw RTE_LOC;
		if(input.rows() != mRows)
			throw RTE_LOC;
		for (auto i : oc::rng(input.mColumns.size()))
			if (input.mColumns[i].getColumnInfo() != mColumns[i])
				throw std::runtime_error(LOCATION);

		// set the inputs
		mGmw.setInput(mWhereInputs.size(), matrixCast<u8>(input.mIsActive));
		for (auto i : oc::rng(mWhereInputs.size()))
			mGmw.setInput(i, input.mColumns[mWhereInputs[i]].mData);

		mGmw.mDebugPrintIdx = 13;
		// eval the where clause and AND with the isActive flag.
		co_await mGmw.run(sock);

		// copy the output
		if (&input != &output)
			output = input;

		// update the isActive flag with the output of the where clause.
		output.mIsActive.resize(mRows);
		mGmw.getOutput(0, matrixCast<u8>(output.mIsActive));

		// optionall remove inactive rows.
		if (mRemoveInactive)
		{
			co_await mRemoveInactive->apply(output, output, sock, prng);
		}
	}



}