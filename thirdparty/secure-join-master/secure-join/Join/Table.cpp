#include "Table.h"
#include "secure-join/Util/Util.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/TableOps/Where.h"
#include "secure-join/Join/OmJoin.h"

namespace secJoin
{

	Perm ColRef::sort()const
	{
		return secJoin::sort(mCol.mData);
	}

	void populateOutTable(Table& out, BinMatrix& actFlag, BinMatrix& data)
	{
		if (out.getColumnInfo().size() == 0)
			throw std::runtime_error("out table not initialzied with column info " LOCATION);

		if (actFlag.numEntries() == 0)
			throw std::runtime_error("ActFlag is empty " LOCATION);

		u64 nOutRows = out.rows();

		u64 curPtr = 0;
		for (u64 i = 0; i < actFlag.numEntries(); i++)
		{
			u64 byteStartIdx = 0;
			if (actFlag(i, 0) == 1)
			{
				// dump data into the out
				for (u64 j = 0; j < out.cols(); j++)
				{
					auto bytes = out.mColumns[j].getByteCount();
					osuCrypto::copyBytes(out.mColumns[j].mData[curPtr], data.mData[i].subspan(byteStartIdx, bytes));
					byteStartIdx += bytes;
				}
				curPtr++;
			}

			if (curPtr >= nOutRows)
				break;
		}
	}




	void Table::writeBin(std::ostream& out)
	{
		u64 c =  mColumns.size(), r = rows();
		out.write((char*)&c, sizeof(c));
		out.write((char*)&r, sizeof(r));

		for (u64 i = 0; i < mColumns.size(); ++i)
		{
			u64 nameSize = mColumns[i].mName.size();
			out.write((char*)&nameSize, sizeof(nameSize));
			out.write(mColumns[i].mName.data(), nameSize);
			out.write((char*)&mColumns[i].mType, sizeof(mColumns[i].mType));
			out.write((char*)&mColumns[i].mBitCount, sizeof(mColumns[i].mBitCount));
		}
		for (u64 i = 0; i < mColumns.size(); ++i)
		{
			out.write((char*)mColumns[i].mData.data(), mColumns[i].mData.size());
		}
	}

	void Table::readBin(std::istream& in)
	{
		u64 cols = 0, rows = 0;
		in.read((char*)&cols, sizeof(cols));
		in.read((char*)&rows, sizeof(rows));
		mColumns.resize(cols);
		for (u64 i = 0; i < cols; ++i)
		{
			std::string name;
			u64 nameSize = 0, bits = 0;
			ColumnType type;
			in.read((char*)&nameSize, sizeof(nameSize));
			if (nameSize > 512)
				throw RTE_LOC;
			name.resize(nameSize);
			in.read((char*)name.data(), name.size());
			in.read((char*)&type, sizeof(type));
			if((u64)type > (u64)ColumnType::Bin)
				throw RTE_LOC;
			in.read((char*)&bits, sizeof(bits));
			if (bits > (1 << 14))
				throw RTE_LOC;
			mColumns[i] = { name, type, bits };
		}

		for (u64 i = 0; i < cols; ++i)
		{
			mColumns[i].mData.resize(rows, mColumns[i].mBitCount);
			in.read((char*)mColumns[i].mData.data(), mColumns[i].mData.size());
		}
	}

	void Table::writeCSV(std::ostream& out)
	{
		out << mColumns.size() << " " << rows() << "\n";
		for (u64 i = 0; i < mColumns.size(); ++i)
		{
			out << mColumns[i].mName << " " << (int)mColumns[i].mType << " " << mColumns[i].mBitCount << "\n";
		}

		for (u64 i = 0; i < rows(); ++i)
		{
			for (u64 j = 0; j < mColumns.size(); ++j)
			{
				if (mColumns[j].mType == ColumnType::Int)
				{
					if (mColumns[j].mBitCount > 64)
						throw RTE_LOC; // too big of an int to serialize
					i64 v = 0;
					osuCrypto::copyBytesMin(v, mColumns[j].mData[i]);
					out << v << " ";
				}
				else if (mColumns[j].mType == ColumnType::Boolean)
				{
					out << (mColumns[j].mData(i, 0) & 1) << " ";
				}
				else if (mColumns[j].mType == ColumnType::String)
				{
					auto b = mColumns[j].mData[i];
					auto j = std::find(b.begin(), b.end(), ';');
					if (j != b.end())
						throw RTE_LOC; // ; is the delimiter, not allowed as data.

					auto e = std::find(b.begin(), b.end(), 0);
					if (e != b.end())
					{
						for (auto i = e + 1; i != b.end(); ++i)
							if (*i != 0)
								throw RTE_LOC; // after the null terminator, all elements must be 0
					}
					out << std::string(b.begin(), e) << ';';
				}
				else if (mColumns[j].mType == ColumnType::Bin)
				{
					out << hex(mColumns[j].mData[i]) << " ";
				}
				else
				{
					throw std::runtime_error(LOCATION);
				}
			}
			out << "\n";
		}
	}

	void Table::readCSV(std::istream& in) {
		std::string buffer;

		std::getline(in, buffer, ' ');
		u64 cols = std::stoll(buffer);
		if (buffer != std::to_string(cols))
			throw RTE_LOC;
		std::getline(in, buffer, '\n');
		u64 rows = std::stoll(buffer);
		if (buffer != std::to_string(rows))
			throw RTE_LOC;

		mColumns.resize(cols);
		for (u64 i = 0; i < cols; ++i)
		{
			std::string name;
			std::getline(in, name, ' ');
			std::getline(in, buffer, ' ');
			u64 type = std::stoll(buffer);
			if (type > (u64)ColumnType::Bin)
				throw RTE_LOC;
			if (std::to_string(type) != buffer)
				throw RTE_LOC;
			std::getline(in, buffer, '\n');
			u64 size = std::stoll(buffer);
			if (std::to_string(size) != buffer)
				throw RTE_LOC;

			mColumns[i] = { name, (ColumnType)type, size };
			mColumns[i].mData.resize(rows, size);
		}

		for (u64 i = 0; i < rows; ++i)
		{
			for (u64 j = 0; j < cols; ++j)
			{
				if (mColumns[j].mType == ColumnType::Int)
				{
					if (mColumns[j].mBitCount > 64)
						throw RTE_LOC;
					std::getline(in, buffer, ' ');
					auto v = std::stoll(buffer);
					if (std::to_string(v) != buffer)
						throw RTE_LOC;

					osuCrypto::copyBytesMin(mColumns[j].mData[i], v);
				}
				else if(mColumns[j].mType == ColumnType::Boolean)
				{
					std::getline(in, buffer, ' ');
					auto v = std::stoll(buffer);
					if (v > 1 || std::to_string(v) != buffer)
						throw RTE_LOC;
					mColumns[j].mData(i, 0) = v;
				}
				else if (mColumns[j].mType == ColumnType::String)
				{
					std::getline(in, buffer, ';');
					auto b = mColumns[j].mData[i];
					if (buffer.size() > b.size())
					{
						std::cout << "intput `" << buffer << "` is too long, max=" << b.size() << std::endl;
						throw RTE_LOC;
					}
					std::copy(buffer.begin(), buffer.end(), b.begin());
					std::fill(b.begin() + buffer.size(), b.end(), 0);
				}
				else if (mColumns[j].mType == ColumnType::Bin)
				{
					std::getline(in, buffer, ' ');
					auto b = mColumns[j].mData[i];
					fromHex(buffer, b);
				}
				else
				{
					throw std::runtime_error(LOCATION);
				}
			}
			std::getline(in, buffer, '\n');
			if (buffer.size())
				throw RTE_LOC;
		}
	}

	void Table::permute(Perm& perm, PermOp op)
	{
		for (u64 i = 0; i < cols(); i++)
		{
			BinMatrix temp(mColumns[i].mData.numEntries(),
				mColumns[i].mData.bitsPerEntry());
			perm.apply<u8>(mColumns[i].mData, temp, op);
			std::swap(mColumns[i].mData, temp);
		}

		if (mIsActive.size() > 0)
		{
			std::vector<u8> temp;
			if (op == PermOp::Regular)
				temp = perm.apply<u8>(mIsActive);
			else
				temp = perm.applyInv<u8>(mIsActive);

			std::swap(mIsActive, temp);
		}
	}

	void Table::share(
		std::array<Table, 2>& shares,
		PRNG& prng)
	{
		shares[0].mColumns.resize(mColumns.size());
		shares[1].mColumns.resize(mColumns.size());
		for (oc::u64 i = 0; i < mColumns.size(); i++)
		{
			std::array<BinMatrix, 2> temp;
			secJoin::share(mColumns[i].mData, temp[0], temp[1], prng);

			for (u64 k = 0; k < 2; ++k)
			{
				shares[k].mColumns[i].mBitCount = mColumns[i].mBitCount;
				shares[k].mColumns[i].mName = mColumns[i].mName;
				shares[k].mColumns[i].mType = mColumns[i].mType;
				shares[k].mColumns[i].mData = temp[k];
			}
		}

		shares[0].mIsActive.resize(mIsActive.size());
		shares[1].mIsActive.resize(mIsActive.size());

		prng.get(shares[0].mIsActive.data(), shares[0].mIsActive.size());
		for (u64 i = 0; i < mIsActive.size(); i++)
			shares[1].mIsActive[i] = shares[0].mIsActive[i] ^ mIsActive[i];

	}


	void Table::extractActive()
	{
		if (mIsActive.size() == 0)
			return;

		u64 curPtr = 0;
		for (u64 i = 0; i < rows(); i++)
		{
			if (mIsActive[i] == 1)
			{
				if (curPtr != i)
				{
					for (u64 j = 0; j < cols(); j++)
					{
						osuCrypto::copyBytes(
							mColumns[j].mData[curPtr],
							mColumns[j].mData[i]);
					}
				}
				curPtr++;
			}
		}

		mIsActive.resize(0);
		for (u64 j = 0; j < cols(); j++)
		{
			mColumns[j].mData.resize(curPtr, mColumns[j].mData.bitsPerEntry());
		}
	}

	macoro::task<> Table::revealLocal(coproto::Socket& sock, Table& out) const
	{
		auto remoteShare = Table();
		auto i = u64();

		remoteShare.init(rows(), getColumnInfo());
		for (i = 0; i < remoteShare.mColumns.size(); i++)
		{
			co_await sock.recv(remoteShare.mColumns[i].mData.mData);
		}
		if (mIsActive.size() > 0)
		{
			remoteShare.mIsActive.resize(mIsActive.size());
			co_await sock.recv(remoteShare.mIsActive);
		}

		out = reveal(*this, remoteShare, false);
	}


	macoro::task<> Table::revealRemote(coproto::Socket& sock) const
	{

		for (u64 i = 0; i < mColumns.size(); i++)
		{
			co_await sock.send(coproto::copy(mColumns[i].mData.mData));
		}

		// std::move() will the delete the local share
		if (mIsActive.size() > 0)
		{
			co_await sock.send(coproto::copy(mIsActive));
		}
	}



	void Table::where(
		span<u64> inputColumns,
		oc::BetaCircuit& whereClause)
	{
		auto cir = Where::makeWhereClause(whereClause);

		std::vector<oc::BitVector> inputs(1+inputColumns.size()), outputs(1);
		inputs[0].resize(0);
		for (u64 i = 0; i < inputs.size(); ++i)
		{
			inputs[1 + i].resize(cir.mInputs[i].size());
			if (inputs[1 + i].size() != mColumns[i].getBitCount())
				throw std::runtime_error(LOCATION);
		}
		outputs[0].resize(1);

		for (u64 j = 0; j < rows(); j++)
		{
			inputs[0][0] = mIsActive[j];
			for (u64 i = 0; i < inputColumns.size(); ++i)
				osuCrypto::copyBytes(inputs[1 + i], mColumns[inputColumns[i]].mData[j]);

			cir.evaluate(inputs, outputs);
			mIsActive[j] = outputs[0][0];
		}
	}

	void Table::sort()
	{
		for (u64 i = 0; i < mColumns.size(); ++i)
		{
			auto p = (*this)[mColumns.size() - 1 - i].sort();
			permute(p, PermOp::Regular);
		}
	}


	//void readBinFile(Table& tb, std::istream& in, oc::u64 rowCount)
	//{
	//    u64 totalBytes = 0;
	//    for (u64 i = 0; i < tb.cols(); i++)
	//        totalBytes += tb.mColumns[i].getByteCount();

	//    std::vector<char> b(totalBytes * BATCH_READ_ENTRIES, 0);
	//    span<char> buffer = b;
	//    u64 rowPtr = 0;
	//    while (!in.eof()) {
	//        in.read(buffer.data(), buffer.size());
	//        std::streamsize readBytes = in.gcount();

	//        // Checking if the file has enough bytes
	//        if (readBytes % totalBytes != 0)
	//            throw RTE_LOC;

	//        u64 rows = readBytes / totalBytes;

	//        if (rowPtr + rows > rowCount)
	//            throw RTE_LOC;

	//        u64 buffptr = 0;
	//        for (oc::u64 rowNum = 0; rowNum < rows; rowNum++, rowPtr++)
	//        {
	//            for (oc::u64 colNum = 0; colNum < tb.cols(); colNum++)
	//            {
	//                u64 bytes = tb.mColumns[colNum].getByteCount();
	//                osuCrypto::copyBytes(
	//                    tb.mColumns[colNum].mData[rowPtr],
	//                    buffer.subspan(buffptr, bytes));
	//                buffptr += bytes;
	//            }
	//        }
	//    }
	//}

	//void readTxtFile(Table& tb, std::istream& in, oc::u64 rowCount)
	//{
	//    std::string line, word;

	//    // Skipping the header
	//    getline(in, line);

	//    for (oc::u64 rowNum = 0; rowNum < rowCount; rowNum++)
	//    {
	//        getline(in, line);

	//        oc::u64 colNum = 0;
	//        std::stringstream str(line);
	//        while (getline(str, word, CSV_COL_DELIM))
	//        {
	//            if (tb.mColumns[colNum].getTypeID() == ColumnType::String)
	//            {
	//                osuCrypto::copyBytesMin(tb.mColumns[colNum].mData[rowNum], word);
	//            }
	//            else if (tb.mColumns[colNum].getTypeID() == ColumnType::Int)
	//            {
	//                if (tb.mColumns[colNum].getByteCount() <= 4)
	//                {
	//                    oc::i32 number = stoi(word);
	//                    osuCrypto::copyBytes(tb.mColumns[colNum].mData[rowNum], number);
	//                }
	//                else if (tb.mColumns[colNum].getByteCount() <= 8)
	//                {
	//                    oc::i64 number = stoll(word);
	//                    osuCrypto::copyBytes(tb.mColumns[colNum].mData[rowNum], number);
	//                }
	//                else
	//                {
	//                    std::string temp = tb.mColumns[colNum].mName
	//                        + " can't be stored as int type\n"
	//                        + LOCATION;
	//                    throw std::runtime_error(temp);
	//                }

	//            }

	//            colNum++;
	//        }
	//    }
	//}

	//void populateTable(Table& tb, std::istream& in, oc::u64 rowCount, bool isBin)
	//{
	//    if (isBin)
	//        readBinFile(tb, in, rowCount);
	//    else
	//        readTxtFile(tb, in, rowCount);
	//}

	//void populateTable(Table& tb, std::string& fileName, oc::u64 rowCount, bool isBin)
	//{
	//    std::ifstream file;
	//    if (isBin)
	//        file.open(fileName, std::ifstream::binary);
	//    else
	//        file.open(fileName, std::ios::in);

	//    if (!file.good())
	//    {
	//        std::cout << "Could not open the file " << fileName << std::endl;
	//        throw RTE_LOC;
	//    }
	//    populateTable(tb, file, rowCount, isBin);
	//    file.close();
	//}


	bool eq(span<const u8> l, span<const u8> r)
	{
		assert(l.size() == r.size());
		for (u64 i = 0; i < l.size(); ++i)
			if (l[i] != r[i])
				return false;
		return true;
	}



	void copyTableEntry(
		Table& out,
		ColRef groupByCol,
		std::vector<ColRef> avgCol,
		std::vector<oc::BitVector>& inputs,
		std::vector<u8>& oldActFlag,
		u64 row)
	{

		out.mIsActive.at(row) = oldActFlag.size() > 0 ? oldActFlag.at(row) : 1;

		if (out.mIsActive[row] == 0)
			return;

		u64 m = avgCol.size();
		assert(row < out.rows());
		// Copying the groupby column
		osuCrypto::copyBytes(
			out.mColumns[0].mData[row],
			groupByCol.mCol.mData[row]);

		// Copying the average column
		for (u64 col = 0; col < m; col++)
		{
			assert(out.mColumns.at(col + 1).mData.bytesPerEntry() == inputs.at(2 * col).sizeBytes());
			osuCrypto::copyBytes(
				out.mColumns.at(col + 1).mData[row],
				inputs.at(2 * col));
		}

		// Copying the ones column 
		osuCrypto::copyBytes(
			out.mColumns.at(m + 1).mData[row],
			inputs.at(2 * m));

	}


	void populateOutTable(
		Table& out,
		std::vector<ColRef> avgCol,
		ColRef groupByCol,
		u64 nOutRows)
	{
		u64 m = avgCol.size();
		// u64 n0 = groupByCol.mCol.rows();

		out.mColumns.resize(m + 2); // Average Cols + Group By Cols + Count Col

		// Adding the group by column info
		out.mColumns[0].mName = groupByCol.mCol.mName;
		auto bits = groupByCol.mCol.getByteCount() * 8;
		out.mColumns[0].mBitCount = bits;
		out.mColumns[0].mType = groupByCol.mCol.mType;
		out.mColumns[0].mData.resize(nOutRows, bits);

		// Adding the average cols
		for (u64 i = 0; i < m; i++)
		{
			out.mColumns[i + 1].mName = avgCol[i].mCol.mName;
			auto bits = avgCol[i].mCol.getByteCount() * 8;
			out.mColumns[i + 1].mBitCount = bits;
			out.mColumns[i + 1].mType = avgCol[i].mCol.mType;
			out.mColumns[i + 1].mData.resize(nOutRows, bits);
		}

		// Adding the count col
		out.mColumns[m + 1].mName = "Count";
		out.mColumns[m + 1].mBitCount = sizeof(oc::u64) * 8;
		out.mColumns[m + 1].mType = ColumnType::Int;
		out.mColumns[m + 1].mData.resize(nOutRows, sizeof(oc::u64) * 8);

	}


	oc::BitVector cirEval(oc::BetaCircuit* cir, std::vector<oc::BitVector>& inputs,
		oc::BitVector& output, u8* data, u64 bits, u64 bytes)
	{

		auto size = bytes * 8;
		// Filling extra bits with zero
		u64 rem = size - bits;
		inputs.at(1).reset(rem);
		inputs[1].append(data, bits);

		std::vector<oc::BitVector> tempOutputs = { output };
		cir->evaluate(inputs, tempOutputs);

		return tempOutputs[0];
	}


	void Table::average(
		ColRef groupByCol,
		std::vector<ColRef> avgCol)
	{
		u64 m = avgCol.size();
		u64 n0 = groupByCol.mCol.rows();
		std::vector<u8> actFlag = groupByCol.mTable.mIsActive;

		// Generating the permutation
		auto groupByPerm = groupByCol.sort();

		BinMatrix temp;
		temp.resize(groupByCol.mCol.mData.numEntries(), groupByCol.mCol.mData.bytesPerEntry() * 8);
		groupByPerm.apply<u8>(groupByCol.mCol.mData, temp, PermOp::Regular);
		std::swap(groupByCol.mCol.mData, temp);

		if (actFlag.size() > 0)
			actFlag = groupByPerm.apply<u8>(actFlag);


		// Applying permutation to all the average cols
		for (u64 i = 0; i < m; i++)
		{
			temp.resize(avgCol[i].mCol.mData.numEntries(),
				avgCol[i].mCol.mData.bytesPerEntry() * 8);
			groupByPerm.apply<u8>(avgCol[i].mCol.mData, temp, PermOp::Regular);
			std::swap(avgCol[i].mCol.mData, temp);
		}


		// Adding a Columns of 1's for calculating average
		BinMatrix ones(n0, sizeof(oc::u64) * 8);
		for (oc::u64 i = 0; i < n0; i++)
			ones(i, 0) = 1;

		Table out;

		populateOutTable(out, avgCol, groupByCol, n0);
		out.mIsActive.resize(n0);


		// Creating a vector of inputs for Beta Circuit evaluation
		std::vector<oc::BetaCircuit*> cir;
		cir.resize(m + 1);
		std::vector<oc::BitVector> inputs(2 * cir.size()), outputs(cir.size());

		oc::BetaLibrary lib;
		for (u64 i = 0; i < m; i++)
		{
			u64 size = avgCol[i].mCol.getByteCount() * 8;
			cir[i] = lib.int_int_add(size, size, size, oc::BetaLibrary::Optimized::Depth);
			inputs[2 * i].reset(size);
			outputs[i].reset(size);

		}

		// Adding the ciruit for the BinMatrix of ones
		u64 size = ones.bytesPerEntry() * 8;
		cir[m] = lib.int_int_add(size, size, size, oc::BetaLibrary::Optimized::Depth);
		inputs[2 * m].reset(size);
		outputs[m].reset(size);

		for (i64 row = n0 - 1; row >= 0; row--)
		{

			if ((row < i64(n0) - 1) && !eq(groupByCol.mCol.mData[row], groupByCol.mCol.mData[row + 1]))
			{
				copyTableEntry(out, groupByCol, avgCol, inputs, actFlag, row + 1);

				// reset the 2 * i location for input
				for (u64 i = 0; i < m; i++)
				{
					u64 size = avgCol[i].mCol.getByteCount() * 8;
					inputs[2 * i].reset(size);
				}
				u64 size = ones.bytesPerEntry() * 8;
				inputs[2 * m].reset(size);
			}


			// Running Circuit for each cols
			for (u64 col = 0; col < m; col++)
			{
				std::vector<oc::BitVector> tempInputs =
				{ inputs[2 * col], inputs[2 * col + 1] };

				inputs[2 * col] = cirEval(cir[col], tempInputs,
					outputs[col], avgCol[col].mCol.mData.data(row),
					avgCol[col].mCol.getBitCount(),
					avgCol[col].mCol.getByteCount()
				);
			}

			// Run the circuit of ones:
			std::vector<oc::BitVector> tempInputs = { inputs[2 * m], inputs[2 * m + 1] };
			inputs[2 * m] = cirEval(cir[m], tempInputs,
				outputs[m], ones.mData.data(row),
				ones.bitsPerEntry(),
				ones.bytesPerEntry()
			);

			if (row == 0)
				copyTableEntry(out, groupByCol, avgCol, inputs, actFlag, row);

		}

		// Applying inverse perm to all the columns
		auto permBackward = PermOp::Inverse;

		auto backPerm = groupByPerm;//remDummies&& randPerm.size() > 0
			//? randPerm : groupByPerm;


		for (u64 i = 0; i < out.cols(); i++)
		{
			temp.resize(out[i].mCol.mData.numEntries(),
				out[i].mCol.mData.bytesPerEntry() * 8);
			backPerm.apply<u8>(out[i].mCol.mData, temp, permBackward);
			std::swap(out[i].mCol.mData, temp);
		}

		// Applying inverse perm to the active flag
		out.mIsActive = backPerm.applyInv<u8>(out.mIsActive);

		//if (remDummies)
		//{
		//	out.extractActive();
		//}
		*this = out;
		//return out;
	}





	Table join(
		const ColRef& l,
		const ColRef& r,
		std::vector<ColRef> select)
	{
		if (l.mCol.getBitCount() != r.mCol.getBitCount())
			throw RTE_LOC;
		auto LPerm = l.sort();
		auto RPerm = r.sort();

		std::vector<std::array<u64, 3>> I;
		I.reserve(r.mCol.rows());

		u64 lIdx = 0;
		for (u64 i = 0; i < r.mCol.rows(); ++i)
		{
			while (
				lIdx < l.mCol.rows() &&
				lessThan(l.mCol.mData[LPerm[lIdx]], r.mCol.mData[RPerm[i]]))
			{
				if (lIdx)
				{
					if (eq(l.mCol.mData[LPerm[lIdx - 1]], l.mCol.mData[LPerm[lIdx]]))
						throw RTE_LOC;// L duplicate key
				}
				++lIdx;
			}

			if (lIdx < l.mCol.rows())
			{
				if (eq(l.mCol.mData[LPerm[lIdx]], r.mCol.mData[RPerm[i]]))
				{
					I.push_back({ LPerm[lIdx], RPerm[i], i });
				}
			}
		}

		std::vector<ColumnInfo> colInfo(select.size());
		for (u64 i = 0; i < colInfo.size(); ++i)
		{
			if (&select[i].mTable != &l.mTable &&
				&select[i].mTable != &r.mTable)
				throw std::runtime_error("select statement doesnt match Left and Right table.");

			colInfo[i] = select[i].mCol.getColumnInfo();
		}
		Table ret(r.mCol.rows(), colInfo);
		ret.mIsActive.resize(r.mCol.rows());

		for (u64 i = 0; i < I.size(); ++i)
		{
			auto d = I[i][2];
			for (u64 j = 0; j < colInfo.size(); ++j)
			{

				auto lr = (&select.at(j).mTable == &r.mTable) ? 1 : 0;
				// auto src = select[j].mCol.mData.data(I[i][lr]);
				// auto dst = ret.mColumns[j].mData.data(d);
				// auto size = ret.mColumns[j].mData.cols();
				// m emcpy(dst, src, size);

				osuCrypto::copyBytes(ret.mColumns.at(j).mData[d], select.at(j).mCol.mData[I.at(i).at(lr)]);
			}
			ret.mIsActive.at(d) = 1;

		}

		return ret;
	}

	std::ostream& operator<<(std::ostream& o, const Table& t)
	{
		auto width = 8;
		auto separator = ' ';
		auto printElem = [&](auto&& t)
			{
				o << std::left << std::setw(width) << std::setfill(separator) << t << " ";
			};

		o << "      ";
		for (u64 i = 0; i < t.mColumns.size(); ++i)
			printElem(t.mColumns[i].mName);

		std::cout << "\n-------------------------------" << std::endl;
		for (u64 i = 0; i < t.rows(); ++i)
		{
			o << std::setw(2) << std::setfill(' ') << i << " ";
			if (t.mIsActive.size())
				o << (int)t.mIsActive[i];
			else
				o << 1;

			o << ": ";
			for (u64 j = 0; j < t.mColumns.size(); ++j)
			{
				if (t.mColumns[j].mType == ColumnType::String)
					printElem(std::string((const char*)t.mColumns[j].mData.data(i), t.mColumns[j].getByteCount()));
				else if (t.mColumns[j].mType == ColumnType::Int)
				{
					if (t.mColumns[j].getBitCount() > 64)
						throw RTE_LOC;
					i64 v = 0;
					osuCrypto::copyBytesMin(v, t.mColumns[j].mData[i]);
					printElem(v);
				}
				else
					printElem(hex(t.mColumns[j].mData.data(i), t.mColumns[j].getByteCount()));
			}
			o << "\n";

		}

		return o;

	}


}
