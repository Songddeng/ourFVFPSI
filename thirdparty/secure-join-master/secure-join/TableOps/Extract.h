#pragma once

#include "secure-join/Util/Matrix.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "secure-join/Perm/Permutation.h"
#include "secure-join/Perm/AltModComposedPerm.h"
#include "secure-join/Util/Util.h"

namespace secJoin {

	// This protocol obliviously extract all active (non-null) rows from the input table.
	// The output will be in a random order.
	struct Extract
	{
		// the number of rows in the input table.
		u64 mRows = 0;

		// the random permutation that is used to shuffle the
		// rows of the input table.
		ComposedPerm mPermutation;

		// the protocol for generating the random permutation correlation
		AltModComposedPerm mPermGen;

		Extract() = default;
		Extract(const Extract&) = delete;
		Extract(Extract&&) = default;
		Extract& operator=(const Extract&) = delete;
		Extract& operator=(Extract&&) = default;

		Extract(u64 rows, u64 bytesPerEntry, CorGenerator& ole)
		{
			init(rows, bytesPerEntry, ole);
		}

		// initialize the protocol for extracting the active subset.
		// `rows` is the number of rows in the input table.
		// `bytesPerEntry` is the number of bytes per entry in the input table.
		// `ole` is the source of the correlated randomness.
		void init(
			u64 rows,
			u64 bytesPerEntry,
			CorGenerator& ole);

		// initialize the protocol for extracting the active subset.
		// `rows` is the number of rows in the input table.
		// `colInfo` the list of column information of the input table.
		// `ole` is the source of the correlated randomness.
		void init(
			u64 rows,
			span<ColumnInfo> colInfos,
			CorGenerator& ole);

		void preprocess() { mPermGen.preprocess(); }

		// extract the active rows from the `input` table and
		// write the result to `output`. `input` and `output` can be the same.
		// `sock` is the socket that the protocol will use to communicate.
		// `prng` is the source of randomness.
		macoro::task<> apply(
			const Table& input,
			Table& output,
			coproto::Socket& sock,
			PRNG& prng);

		// extract the active rows from the `input` table and
		// write the result to `output`. 
		// `extractionFlags` is the list of active rows.
		// `input` and `output` can be the same.
		// `sock` is the socket that the protocol will use to communicate.
		// `prng` is the source of randomness.
		macoro::task<> apply(
			span<const u8> extractionFlags,
			span<const BinMatrix*> input,
			span<BinMatrix*> output,
			coproto::Socket& sock,
			PRNG& prng);

	};
}