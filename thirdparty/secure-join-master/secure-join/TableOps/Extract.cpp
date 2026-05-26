#include "Extract.h"
#include "secure-join/Join/OmJoin.h"
#include "GroupBy.h"

namespace secJoin {

	void Extract::init(
		u64 rows,
		u64 bytesPerEntry,
		CorGenerator& ole)
	{
		mRows = rows;
		mPermGen.init(ole.partyIdx(), rows, bytesPerEntry, ole);
	}

	void Extract::init(
		u64 rows,
		span<ColumnInfo> colInfos,
		CorGenerator& ole)
	{
		u64 bytesPerEntry = 0;
		for (auto& info : colInfos)
			bytesPerEntry += info.getByteCount();

		init(rows, bytesPerEntry, ole);
	}

	macoro::task<> Extract::apply(const Table& input, Table& output, coproto::Socket& sock, PRNG& prng)
	{
		if (input.mIsActive.size() != mRows)
			throw RTE_LOC;

		std::vector<const BinMatrix*> in(input.mColumns.size());
		for (u64 i = 0; i < input.mColumns.size(); i++)
			in[i] = &input.mColumns[i].mData;

		if (output.mColumns.size() != input.mColumns.size())
			output.init(0, input.getColumnInfo());

		std::vector<BinMatrix*> out(input.mColumns.size());
		for (u64 i = 0; i < output.mColumns.size(); i++)
			out[i] = &output.mColumns[i].mData;


		co_await apply(input.mIsActive, in, out, sock, prng);

		// all rows are active.
		output.mIsActive.resize(0);
	}

	// zip the input matrices into one matrix. The ith row of each
	// input forms one large row in the output matrix.
	auto combine(span<oc::MatrixView<const u8>> input)
	{
		if (!input.size())
			throw RTE_LOC;
		u64 s = 0;
		u64 r = input[0].rows();
		for (u64 i = 0; i < input.size(); ++i)
		{
			if (input[i].rows() != r)
				throw RTE_LOC;

			s += input[i].cols();
		}

		BinMatrix dst(r, s * 8);
		for (u64 i = 0; i < r; ++i)
		{
			auto d = dst.mData[i];
			for (u64 j = 0; j < input.size(); ++j)
			{
				osuCrypto::copyBytes(d.subspan(0, input[j].cols()), input[j][i]);
				d = d.subspan(input[j].cols());
			}
		}

		return dst;
	}

	// unzip the input matrix into the output matrices. The ith row of the input
	// matrix is split into the ith row of each output matrix.
	void separate(const BinMatrix& input, span<oc::MatrixView<u8>> output)
	{
		if (!output.size())
			throw RTE_LOC;
		u64 s = 0;
		u64 r = input.rows();
		for (u64 i = 0; i < output.size(); ++i)
		{
			if (output[i].rows() != r)
				throw RTE_LOC;

			s += output[i].cols();
		}

		if (s != input.cols())
			throw RTE_LOC;

		for (u64 i = 0; i < r; ++i)
		{
			auto d = input[i];
			for (u64 j = 0; j < output.size(); ++j)
			{
				osuCrypto::copyBytes(output[j][i], d.subspan(0, output[j].cols()));
				d = d.subspan(output[j].cols());
			}
		}
	}

	macoro::task<> Extract::apply(
		span<const u8> extractionFlags,
		span<const BinMatrix*> input,
		span<BinMatrix*> output,
		coproto::Socket& sock,
		PRNG& prng)
	{
		if (extractionFlags.size() != mRows)
			throw RTE_LOC;
		if (input.size() != output.size())
			throw RTE_LOC;
		for (u64 i = 0; i < input.size(); i++)
			if (input[i]->rows() != mRows)
				throw RTE_LOC;

		// mPerm by default generates a random perm
		co_await mPermGen.generate(sock, prng, Perm(mRows, prng), mPermutation);

		// combine the extraction flags and input into one matrix.
		std::vector<oc::MatrixView<const u8>> in(1 + input.size());
		in[0] = matrixCast<const u8>(extractionFlags);
		for (u64 i = 0; i < input.size(); i++)
			in[i + 1] = *input[i];
		BinMatrix combined = combine(in);

		// apply the random permutation
		co_await mPermutation.apply<u8>(PermOp::Regular, combined, combined, sock);

		// reveal the extraction flags
		oc::BitVector flags(extractionFlags.size()), buff(extractionFlags.size());
		for (u64 i = 0; i < flags.size(); ++i)
			flags[i] = combined(i, 0) & 1;
		co_await macoro::when_all_ready(
			sock.send(flags),
			sock.recv(buff)
		);
		flags ^= buff;

		//if (mDebug)
		//{
		//	BinMatrix control;
		//	std::vector<OmJoin::Offset> offsets(in.size());
		//	offsets[0].mName = "flags";
		//	offsets[0].mStart = 0;	
		//	offsets[0].mSize = 1;
		//	for (u64 i = 0; i < input.size(); ++i)
		//	{
		//		offsets[i + 1].mName = "input" + std::to_string(i);
		//		offsets[i + 1].mStart = offsets[i].mStart + oc::roundUpTo(offsets[i].mSize, 8);
		//		offsets[i + 1].mSize = input[i]->bitsPerEntry();
		//	}

		//	co_await OmJoin::print(combined, control, sock, mPermutation.mPartyIdx, "extract", offsets);
		//}

		// construct the output. Only rows with flag=1 are kept.
		u64 w = flags.hammingWeight();
		for (u64 i = 0; i < output.size(); ++i)
			output[i]->resize(w, input[i]->bitsPerEntry());
		for (u64 i = 0, d = 0; i < flags.size(); ++i)
		{
			if (flags[i])
			{
				auto src = combined[i].subspan(1);
				for (u64 j = 0; j < output.size(); ++j)
				{
					osuCrypto::copyBytes((*output[j])[d], src.subspan(0, output[j]->bytesPerEntry()));
					src = src.subspan(output[j]->bytesPerEntry());
				}
				++d;
			}
		}
	}

}