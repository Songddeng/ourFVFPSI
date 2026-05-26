#pragma once
#include "secure-join/Join/Table.h"


namespace secJoin
{

	struct JoinQuerySchema
	{
		struct SelectCol
		{
			ColumnInfo mCol;
			bool mIsLeftColumn;
			u64 getBitCount() const { return mCol.getBitCount(); }
			u64 getByteCount() const { return mCol.getByteCount(); }
			std::string name() const { return mCol.mName; }
		};
		u64 mLeftSize = 0, mRightSize = 0;
		ColumnInfo mKey;
		std::vector<SelectCol> mSelect;
	};

	struct JoinQuery
	{
		// the unique join key.
		ColRef mLeftKey;

		// the join key with duplicates.
		ColRef mRightKey;

		// the columns to be selected.
		std::vector<ColRef> mSelect;

		bool isUnion() const { return false; }

		JoinQuery(const ColRef& leftKey, const ColRef& rightKey, std::vector<ColRef> select)
			: mLeftKey(leftKey)
			, mRightKey(rightKey)
			, mSelect(std::move(select))
		{
			for (auto& c : mSelect)
			{
				if (&c.mTable != &mLeftKey.mTable &&
					&c.mTable != &mRightKey.mTable)
					throw RTE_LOC;
			}

			if (mLeftKey.mCol.getBitCount() != mRightKey.mCol.getBitCount())
				throw RTE_LOC;
		}

		operator JoinQuerySchema()
		{
			JoinQuerySchema ret;
			ret.mLeftSize = mLeftKey.mTable.rows();
			ret.mRightSize = mRightKey.mTable.rows();
			ret.mKey = mLeftKey.mCol.getColumnInfo();
			for (auto& c : mSelect)
			{
				ret.mSelect.push_back({ c.mCol.getColumnInfo(), &c.mTable == &mLeftKey.mTable });
			}
			return ret;
		}
	};


	Table join(
		const ColRef& l,
		const ColRef& r,
		std::vector<ColRef> select);

}