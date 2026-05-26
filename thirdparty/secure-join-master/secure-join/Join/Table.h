#pragma once

#include "coproto/Common/span.h"
#include <cryptoTools/Common/MatrixView.h>
#include <fstream>
#include "secure-join/Util/Matrix.h"
#include "secure-join/Defines.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Circuit/BetaCircuit.h"
#include "secure-join/Util/ArrGate.h"
#include "secure-join/Perm/Permutation.h"
#include <vector>
#include <set>
#include <string>

namespace secJoin
{
	inline void fromHex(char a, char b, u8& out)
	{
		out = 0;
		if (a >= '0' && a <= '9')
			out = (a - '0') << 4;
		else if (a >= 'a' && a <= 'f')
			out = (a - 'a' + 10) << 4;
		else if (a >= 'A' && a <= 'F')
			out = (a - 'A' + 10) << 4;
		else
			throw std::runtime_error(LOCATION);

		if (b >= '0' && b <= '9')
			out |= (b - '0');
		else if (b >= 'a' && b <= 'f')
			out |= (b - 'a' + 10);
		else if (b >= 'A' && b <= 'F')
			out |= (b - 'A' + 10);
		else
			throw std::runtime_error(LOCATION);
	}

	inline void fromHex(const std::string& data, span<u8> dst)
	{
		if (data.size() != dst.size() * 2)
			throw std::runtime_error(LOCATION);

		for (u64 i = 0; i < dst.size(); ++i)
		{
			fromHex(data[i * 2], data[i * 2 + 1], dst[i]);
		}
	}

	enum class ColumnType : u8
	{
		Int = 0,
		Boolean = 1,
		String = 2,
		Bin = 3,
	};

	struct ColumnInfo
	{
		ColumnInfo() = default;
		ColumnInfo(std::string name, ColumnType type, u64 size)
			: mName(std::move(name))
			, mType(type)
			, mBitCount(size)
		{
			if (mType == ColumnType::String && mBitCount % 8)
				throw std::runtime_error("String type must have a multiple of 8 bits. " LOCATION);
		}

		u64 getBitCount() const { return mBitCount; }
		u64 getByteCount() const { return oc::divCeil(mBitCount, 8); }

		std::string mName;
		ColumnType mType;
		u64 mBitCount = 0;


		bool operator==(const ColumnInfo& o) const
		{
			return mName == o.mName && mType == o.mType && mBitCount == o.mBitCount;
		}
		bool operator!=(const ColumnInfo& o) const
		{
			return !(*this == o);
		}
	};

	class Column : public ColumnInfo
	{
	public:
		Column() = default;
		Column(const Column&) = default;
		Column(Column&&) = default;
		Column& operator=(const Column&) = default;
		Column& operator=(Column&&) = default;

		Column(std::string name, ColumnType type, u64 size)
			: ColumnInfo(std::move(name), type, size)
		{}

		u64 getByteCount() const { return (getBitCount() + 7) / 8; }
		u64 getBitCount() const { return mBitCount; }
		ColumnType getTypeID() const { return mType; }

		secJoin::BinMatrix mData;

		u8* data() { return mData.data(); }
		auto size() { return mData.size(); }
		const u8* data() const { return mData.data(); }
		u64 rows() { return mData.rows(); }
		u64 cols() { return mData.cols(); }


		ColumnInfo getColumnInfo() const
		{
			return { mName, mType, mBitCount };
		}

		bool operator!=(const Column& o) const
		{
			return !(*this == o);
		}
		bool operator==(const Column& o) const
		{
			if (mBitCount != o.mBitCount)
				return false;
			if (mName != o.mName)
				return false;
			return mData == o.mData;
		}
	};

	class Table;

	struct ColRef
	{
		Table& mTable;
		Column& mCol;

		ColRef(Table& t, Column& c)
			: mTable(t), mCol(c)
		{
		}

		ColRef(const ColRef&) = default;
		ColRef(ColRef&&) = default;

		// returns the sorting permutation. The smallest comes first.
		Perm sort() const;
	};


	class Table
	{
	public:
		std::vector<u8> mIsActive;
		std::vector<Column> mColumns;

		Table() = default;
		Table(const Table&) = default;
		Table(Table&&) = default;

		Table& operator=(const Table&) = default;
		Table& operator=(Table&&) = default;

		Table(u64 rows, std::vector<ColumnInfo> columns)
		{
			init(rows, columns);
		}

		// initializes the table with the given number of rows and columns.
		void init(u64 rows, std::vector<ColumnInfo> columns)
		{
			mColumns.clear();
			mColumns.reserve(columns.size());
			std::set<std::string> names;

			for (u64 i = 0; i < columns.size(); ++i)
			{
				if(names.insert(columns[i].mName).second == false)
					throw std::runtime_error("Duplicate column name `" + columns[i].mName+ "` @ " + LOCATION);
					
				mColumns.emplace_back(
					columns[i].mName,
					columns[i].mType,
					columns[i].mBitCount);

				mColumns.back().mData.resize(rows, columns[i].mBitCount);
			}
		}

		// returns the column info for each column in the table.
		std::vector<ColumnInfo> getColumnInfo() const
		{
			std::vector<ColumnInfo> ret(mColumns.size());
			for (u64 i = 0; i < ret.size(); ++i)
			{
				ret[i] = mColumns[i].getColumnInfo();
			}
			return ret;
		}

		// resizes the number of rows in the table.
		void resize(u64 n)
		{
			for (u64 i = 0; i < mColumns.size(); ++i)
				mColumns[i].mData.resize(n, mColumns[i].mBitCount);
		}

		// number of rows
		u64 rows() const { return mColumns.size() ? mColumns[0].mData.numEntries() : 0; }

		// number of columns
		u64 cols() { return mColumns.size() ? mColumns.size() : 0; }

		// returns the i'th column
		ColRef operator[](std::string c)
		{
			for (u64 i = 0; i < mColumns.size(); ++i)
			{
				if (mColumns[i].mName == c)
					return { *this, mColumns[i] };
			}

			throw std::runtime_error(c + " Col not found " + LOCATION + "\n");
		}

		// returns the i'th column
		ColRef operator[](u64 i)
		{
			return { *this, mColumns[i] };
		}

		// compares two tables row by row for inequality.
		bool operator!=(const Table& o) const
		{
			return !(*this == o);
		}

		// compares two tables row by row for equality.
		bool operator==(const Table& o) const
		{
			if (getColumnInfo() != o.getColumnInfo())
				return false;
			if (rows() != o.rows())
				return false;

			for (u64 j = 0; j < mColumns.size(); ++j)
			{
				if (mColumns[j] != o.mColumns[j])
					return false;
			}

			return true;
		}


		// reads a binary file containing the table. The format is
		//
		//    c r 
		//    colName[0].size() colName[0] colType[0] colSize[0]
		//    ...
		//    colName[c].size() colName[c] colType[c] colSize[c]
		//    data[0]
		//	  ...
		//	  data[c]
		// 
		// where 
		//    c = number of columns, 64 bits
		//    r = number of rows, 64 bits
		//    colName[i].size() = the size of the column name, 64 bits
		//    colName[i] = the column name string, colName[i].size() bytes
		//    colType[i] = the column type, 8 bits
		//    colSize[i] = the column element bit count, 64 bits
		//    data[i] = the column data, r * colSize[i] bits
		//
		// spaces and new lines are not included.
		void writeBin(std::ostream& out);

		// reads a binary file containing the table. The format is
		//
		//    c r 
		//    colName[0].size() colName[0] colType[0] colSize[0]
		//    ...
		//    colName[c].size() colName[c] colType[c] colSize[c]
		//    data[0]
		//	  ...
		//	  data[c]
		// 
		// where 
		//    c = number of columns, 64 bits
		//    r = number of rows, 64 bits
		//    colName[i].size() = the size of the column name, 64 bits
		//    colName[i] = the column name string, colName[i].size() bytes
		//    colType[i] = the column type, 8 bits
		//    colSize[i] = the column element bit count, 64 bits
		//    data[i] = the column data, r * colSize[i] bits
		//
		// spaces and new lines are not included.
		void readBin(std::istream& in);

		// writes a CSV file containing the table. The format is
		// 
		//    c;r;
		//    colName[0];colType[0];colSize[0];
		//    ...
		//    colName[c];colType[c];colSize[c];
		//    data[0][0];...;data[0][c];
		//    ...
		//    data[r][0];...;data[r][c];
		//
		void writeCSV(std::ostream& out);

		// reads a CSV file containing the table. The format should be
		// 
		//    c;r;
		//    colName[0];colType[0];colSize[0];
		//    ...
		//    colName[c];colType[c];colSize[c];
		//    data[0][0];...;data[0][c];
		//    ...
		//    data[r][0];...;data[r][c];
		//
		void readCSV(std::istream& in);

		// permutes the rows of the table by perm.
		void permute(Perm& perm, PermOp op);


		// outputs a random sharing of the table.
		void share(
			std::array<Table, 2>& shares,
			PRNG& prng);

		// returns a random sharing of the table.
		std::array<Table, 2> share(PRNG& prng) {
			std::array<Table, 2> ret;
			share(ret, prng);
			return ret;
		}

		// extracts all of the active rows into the output table.
		// all inactive rows are removed.
		void extractActive();

		// updates the mIsActive flags based on the where clause.
		// `inputColumns` is the subset of columns that are input 
		// to the where clause.
		void where(
			span<u64> inputColumns,
			oc::BetaCircuit& whereClause);

		// computate the sum of the group by column
		// and appends a "count" column with the counds.
		void average(
			ColRef groupByCol,
			std::vector<ColRef> avgCol);


		// reveal the table to this party. 
		macoro::task<> revealLocal(coproto::Socket& sock, Table& out) const;

		// reveal the shared table to the other party.
		macoro::task<> revealRemote(coproto::Socket& sock) const;

		// Sorts the table. Smallest comes first. The column is the 
		// primary sort key, second ...
		void sort();
	};

	using SharedTable = Table;
	using SharedColumn = Column;

	std::ostream& operator<<(std::ostream& o, const Table& t);

	//oc::BitVector cirEval(
	//	oc::BetaCircuit* cir,
	//	std::vector<oc::BitVector>& inputs,
	//	oc::BitVector& output,
	//	u8* data,
	//	u64 bits,
	//	u64 bytes);

	//// Given the groupbyCol & avgCols it updates the meta data info in the out table
	//// Note this function doesn't add any actual data
	//void populateOutTable(
	//	Table& out,
	//	std::vector<ColRef> avgCol,
	//	ColRef groupByCol,
	//	u64 nOutRows);

	//// Given the actFlag matrix, it populates the out table at the location
	//// where actflag is 1 using the data Matrix
	//void populateOutTable(Table& out, BinMatrix& actFlag, BinMatrix& data);


	//void copyTableEntry(
	//	Table& out,
	//	ColRef groupByCol,
	//	std::vector<ColRef> avgCol,
	//	std::vector<oc::BitVector>& inputs,
	//	std::vector<u8>& oldActFlag,
	//	u64 row);


	//// Call this applyPerm when Table is in plaintext
	//Table applyPerm(Table& T, Perm& perm, PermOp op);

	//void concatTable(Table& T, BinMatrix& out);

	//u64 countActiveRows(Table& T);
	//u64 countActiveRows(std::vector<u8>& actFlag);
	//u64 countActiveRows(oc::MatrixView<u8> actFlag);

}
