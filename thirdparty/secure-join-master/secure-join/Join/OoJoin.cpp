#include "OoJoin.h"
#include <iomanip>

namespace secJoin
{
	void OoJoin::init(
		JoinQuerySchema schema,
		CorGenerator& ole,
		PRNG& prng,
		bool remDummiesFlag)
	{
		auto keySize = std::min<u64>(
			schema.mKey.mBitCount,
			mStatSecParam + log2(schema.mLeftSize) + log2(schema.mRightSize));

		mPartyIdx = ole.partyIdx();
		u64 mDataBitsPerEntry = 0;
		//mRemDummiesFlag = remDummiesFlag;

		mOffsets.clear();
		mOffsets.reserve(schema.mSelect.size() + 1);
		for (u64 i = 0; i < schema.mSelect.size(); ++i)
		{
			// copy all of the left columns except the key
			if (schema.mSelect[i].mIsLeftColumn)
			{
				auto bytes = oc::divCeil(schema.mSelect[i].getBitCount(), 8);
				assert(bytes == schema.mSelect[i].getByteCount());
				mOffsets.emplace_back(
					Offset{
						mDataBitsPerEntry,
						schema.mSelect[i].getBitCount(),
						schema.mSelect[i].name() });

				mDataBitsPerEntry += bytes * 8;
			}
		}

		mOffsets.emplace_back(Offset{ mDataBitsPerEntry, keySize, "key*" });
		mDataBitsPerEntry += schema.mKey.getByteCount() * 8;


		if (mPartyIdx)
		{
			//AltModPrf::KeyType keyShare = prng.get();
			throw RTE_LOC;
			//mSendHasher.init(schema.mLeftSize + schema.mRightSize, ole, keyShare);
			mPermGenSend.init(schema.mRightSize, mDataBitsPerEntry, ole);
			mPermGenRecv.init(schema.mLeftSize* 3, mDataBitsPerEntry, ole);
		}
		else
		{
			//AltModPrf::KeyType keyShare = prng.get();
			throw RTE_LOC;
			//mRecvHasher.init(schema.mLeftSize + schema.mRightSize, ole, keyShare);
			mPermGenRecv.init(schema.mRightSize, mDataBitsPerEntry, ole);
			mPermGenSend.init(schema.mLeftSize * 3, mDataBitsPerEntry, ole);
		}


		if (remDummiesFlag)
		{
			throw RTE_LOC;
			//u64 dateBytesPerEntry = 0;
			//// Setting up the offset for OmJoin::concatColumns
			//for (u64 i = 0; i < schema.mSelect.size(); ++i)
			//{
			//    auto bytes = schema.mSelect[i].getByteCount();
			//    dateBytesPerEntry += bytes;
			//}
			//// Adding Active Flag
			//dateBytesPerEntry += 1;

			//// Here rows would be only elements in right table bcoz
			//// after the unsort entries from the left table are removed
			//mRemDummies.init(schema.mRightSize, dateBytesPerEntry, ole, false);
		}

	}
	
	std::string hexString(u8* ptr, u64 size)
	{
		std::stringstream ss;
		for (u64 i = 0; i < size; ++i)
		{
			ss << std::hex << std::setw(2) << std::setfill('0') << u32(ptr[i]);
		}

		return ss.str();
	}

	std::array<std::vector<ColRef>, 2> OoJoin::groupSelectCols(JoinQuery& query) {
		std::array<std::vector<ColRef>, 2> r;
		for (u64 i = 0; i < query.mSelect.size(); ++i)
		{
			if (&query.mSelect[i].mTable == &query.mLeftKey.mTable)
			{
				r[0].push_back(query.mSelect[i]);
			}
			else
			{
				assert(&query.mSelect[i].mTable == &query.mRightKey.mTable);
				r[1].push_back(query.mSelect[i]);
			}
		}
		return r;
	}


	macoro::task<> OoJoin::join(
		JoinQuery query,
		Table& out,
		PRNG& prng,
		coproto::Socket& sock)
	{
		throw RTE_LOC;
		//setTimePoint("intersect_start");
		//auto& leftTable = query.mLeftKey.mTable;
		//auto& rightTable = query.mRightKey.mTable;

		//auto [leftSelectColumns, rightSelectColumns] = groupSelectCols(query);

		//auto keys = co_await hashKeys(query);

		//if (mPartyIdx)
		//{
		//	auto [perm, table] = cuckooHash(rightSelectColumns, keys);

		//	PermCorSender sendPerm;
		//	co_await mPermGenSend.generate(perm, prng, sock, sendPerm);

		//	BinMatrix tableShare(table.rows(), table.bitsPerEntry());
		//	co_await sendPerm.apply<u8>(PermOp::Regular, tableShare, sock);

		//	for (auto i = 0; i < table.size(); ++i)
		//		table(i) ^= tableShare(i);
		//	tableShare = {};

		//	PermCorReceiver recvPerm;
		//	co_await mPermGenRecv.generate(prng, sock, recvPerm);

		//	BinMatrix tableSelect(leftTable.rows() * 3, table.bitsPerEntry());
		//	co_await recvPerm.apply<u8>(PermOp::Regular, table, tableSelect, sock);

		//	tableSelect.reshape(table.bitsPerEntry() * 3);
		//	assert(tableSelect.rows() == leftTable.rows());

		//	co_await compare(tableSelect, query, out);

		//}
		//else
		//{
		//	PermCorReceiver recvPerm;
		//	co_await mPermGenRecv.generate(prng, sock, recvPerm);

		//	auto tableShare = loadTable(rightSelectColumns);

		//	BinMatrix table(tableShare.rows(), tableShare.bitsPerEntry());
		//	co_await recvPerm.apply<u8>(PermOp::Regular, tableShare, table, sock);
		//	tableShare = {};

		//	BinMatrix tableSelect(leftTable.rows() * 3, table.bitsPerEntry());
		//	auto perm = selectCuckooPos(table, tableSelect, keys);

		//	PermCorSender sendPerm;
		//	co_await mPermGenSend.generate(perm, prng, sock, sendPerm);

		//	tableSelect.reshape(table.bitsPerEntry() * 3);
		//	assert(tableSelect.rows() == leftTable.rows());

		//	co_await compare(tableSelect, query, out);
		//}
	}


	macoro::task<oc::AlignedUnVector<block>> OoJoin::hashKeys(JoinQuery& j)
	{
		oc::AlignedUnVector<block> in(j.mLeftKey.mCol.rows() + j.mRightKey.mCol.rows());
		throw RTE_LOC;
		if (mPartyIdx)
		{

			//mSendHasher;
		}
		else
		{
			//AltModWPrf::KeyType keyShare = prng.get();
			//mRecvHasher.init(schema.mLeftSize + schema.mRightSize, ole, keyShare);
		}

	}


	std::pair<Perm, BinMatrix> OoJoin::cuckooHash(span<ColRef> selects, span<block> keys)
	{
		oc::CuckooParam params = oc::CuckooIndex<>::selectParams(selects[0].mCol.rows(), mStatSecParam, 0, 3);
		oc::CuckooIndex<oc::CuckooTypes::NotThreadSafe> mCuckoo;
		auto& cuckoo = mCuckoo;
		cuckoo.init(params);
		cuckoo.insert(keys);

		u64 totalBytes = 0;
		std::vector<u64> strides(selects.size());
		for (u64 j = 0; j < selects.size(); ++j)
		{
			strides[j] = selects[j].mCol.getByteCount();
			totalBytes += strides[j];
		}

		BinMatrix share0(cuckoo.mBins.size(), totalBytes * 8);
		Perm perm(cuckoo.mBins.size());

		u32 next = static_cast<u32>(keys.size());
		for (u32 i = 0; i < cuckoo.mBins.size(); ++i)
		{
			if (cuckoo.mBins[i].isEmpty() == false)
			{
				auto inputIdx = cuckoo.mBins[i].idx();
				perm.mPi[inputIdx] = i;
				auto dest = share0[i];

				for (u64 j = 0; j < selects.size(); ++j)
				{
					auto src = selects[j].mCol.mData[inputIdx];
					osuCrypto::copyBytes(dest.subspan(0, src.size()), src);
					dest = dest.subspan(src.size());
					// memcpy(dest, src, strides[j]);
					// dest += strides[j];
				}
			}
			else
			{
				perm.mPi[next++] = i;
			}
		}
		return { perm, share0 };
	}



	macoro::task<> OoJoin::compare(
		BinMatrix& rightSelected,
		const JoinQuery& query,
		Table& out)
	{
		throw RTE_LOC;
		co_return;
	}

	//SharedTable OoJoin::rightUnion(
	//	ColRef leftJoinCol,
	//	ColRef rightJoinCol,
	//	std::vector<ColRef> leftSelects,
	//	std::vector<ColRef> rightSelects)
	//{
	//	if (mHasSeed == false)
	//		initSeeds();

	//	setTimePoint("union_start");
	//	//throw RTE_LOC;

	//	auto numCols = leftSelects.size();

	//	if (leftSelects.size() != rightSelects.size())
	//		throw RTE_LOC;

	//	for (u64 i = 0; i < numCols; ++i)
	//	{
	//		if (leftSelects[i].mCol.getTypeID() != rightSelects[i].mCol.getTypeID() ||
	//			leftSelects[i].mCol.getBitCount() != rightSelects[i].mCol.getBitCount())
	//			throw RTE_LOC;
	//	}

	//	auto& leftTable = leftJoinCol.mTable;
	//	auto& rightTable = rightJoinCol.mTable;
	//	//auto maxRows = leftTable.rows() + rightTable.rows();

	//	SelectQuery query;
	//	auto jc = query.joinOn(leftJoinCol, rightJoinCol);
	//	for (auto& c : leftSelects)
	//	{
	//		if (&leftJoinCol.mCol == &c.mCol)
	//			query.addOutput(c.mCol.mName, jc);
	//		else
	//			query.addOutput(c.mCol.mName, query.addInput(c));
	//	}

	//	query.isUnion(true);

	//	// all of the columns out of the right table that need to be selected.
	//	//std::vector<ColRef> circuitInputCols, circuitOutCols;
	//	//SharedTable C;
	//	// all of the columns out of the right table that need to be selected.
	//	SharedTable C;
	//	std::vector<SharedColumn*> leftCircuitInput, rightCircuitInput, circuitOutput;
	//	std::vector<std::array<SharedColumn*, 2>> leftPassthroughCols;

	//	constructOutTable(
	//		// outputs
	//		leftCircuitInput,
	//		rightCircuitInput,
	//		circuitOutput,
	//		leftPassthroughCols,
	//		C,
	//		// inputs 
	//		query);

	//	//constructOutTable(circuitInputCols, circuitOutCols, C, rightJoinCol, leftJoinCol, leftSelects, maxRows, false);

	//	std::array<ColRef, 2> AB{ leftJoinCol,rightJoinCol };
	//	std::array<u64, 2> reveals{ 1,0 };
	//	aby3::i64Matrix keys = computeKeys(AB, reveals);
	//	setTimePoint("union_compute_keys");

	//	// construct a cuckoo table for the right table, then use the keys from left table to select out of the cuckoo table to 
	//	// get three shares of the cuckoo table entries, one for each cuckoo hash function. 
	//	std::array<Matrix<u8>, 3> circuitInputShare =
	//		mapRightTableToLeft(keys, rightCircuitInput, leftTable, rightTable);

	//	// now perform the comparison between the entry from the left table with the three possible matched 
	//	// which were selected out of the cuckoo table.
	//	aby3::sPackedBin intersectionFlags =
	//		unionCompare(leftJoinCol, rightJoinCol, circuitInputShare);

	//	setTimePoint("union_compare");

	//	aby3::PackedBin plainFlags(leftTable.rows(), 1);
	//	mEnc.revealAll(mRt.noDependencies(), intersectionFlags, plainFlags).get();
	//	setTimePoint("union_done");
	//	BitIterator iter((u8*)plainFlags.mData.data(), 0);

	//	std::vector<u64> sizes(numCols);
	//	for (u64 i = 0; i < sizes.size(); ++i)
	//		sizes[i] = leftSelects[i].mCol.getByteCount();

	//	auto size = rightSelects[0].mCol.rows();

	//	for (u64 j = 0; j < numCols; ++j)
	//	{
	//		for (auto b : { 0, 1 })
	//			memcpy(
	//				C.mColumns[j].mShares[b].data(),
	//				rightSelects[j].mCol.mShares[b].data(),
	//				rightSelects[j].mCol.mShares[b].size() * sizeof(i64));
	//	}

	//	for (u64 i = 0; i < leftTable.rows(); ++i)
	//	{
	//		if (*iter == 0)
	//		{
	//			for (u64 j = 0; j < numCols; ++j)
	//			{
	//				auto s0 = &leftSelects[j].mCol.mShares[0](i, 0);
	//				auto s1 = &leftSelects[j].mCol.mShares[1](i, 0);
	//				auto d0 = &C.mColumns[j].mShares[0](size, 0);
	//				auto d1 = &C.mColumns[j].mShares[1](size, 0);

	//				memmove(d0, s0, sizes[j]);
	//				memmove(d1, s1, sizes[j]);
	//			}

	//			++size;
	//		}

	//		++iter;
	//	}

	//	for (u64 j = 0; j < C.mColumns.size(); ++j)
	//	{
	//		C.mColumns[j].resize(size, C.mColumns[j].getBitCount());
	//	}

	//	return C;
	//}




	//std::array<Matrix<u8>, 3> OoJoin::mapRightTableToLeft(
	//	aby3::i64Matrix& keys,
	//	span<SharedColumn*> circuitInputCols,
	//	SharedTable& leftTable,
	//	SharedTable& rightTable)
	//{

	//	auto cuckooParams = CuckooIndex<>::selectParams(rightTable.rows(), OoJoin_ssp, 0, 3);

	//	std::array<Matrix<u8>, 3> circuitInputShare;
	//	switch (mIdx)
	//	{
	//	case 0:
	//	{
	//		if ((u64)keys.rows() != circuitInputCols[0]->rows())
	//			throw RTE_LOC;

	//		// place the right table's select columns into a cuckoo table using the keys as hash values.
	//		auto cuckooTable = cuckooHash(circuitInputCols, cuckooParams, keys);
	//		setTimePoint("intersect_cuckoo_hash");

	//		// based on the keys for the left table, select the corresponding entries out of
	//		// the cuckoo hash table. circuitInputShare will hold three shares per left table entry, 
	//		// one share for each of the three hash function.
	//		circuitInputShare = selectCuckooPos(cuckooTable, leftTable.rows());
	//		setTimePoint("intersect_select_cuckoo");

	//		// debug check to see if this is done correctly.
	//		if (OoJoin_debug)
	//			p0CheckSelect(cuckooTable, circuitInputShare);

	//		break;
	//	}
	//	case 1:
	//	{

	//		// place the right table's select columns into a cuckoo table using the keys as hash values.
	//		auto cuckooTable = cuckooHashRecv(circuitInputCols);
	//		setTimePoint("intersect_cuckoo_hash");

	//		// based on the keys for the left table, select the corresponding entries out of
	//		// the cuckoo hash table. circuitInputShare will hold three shares per left table entry, 
	//		// one share for each of the three hash function.
	//		circuitInputShare = selectCuckooPos(cuckooTable, leftTable.rows(), cuckooParams, keys);
	//		setTimePoint("intersect_select_cuckoo");

	//		// debug check to see if this is done correctly.
	//		if (OoJoin_debug)
	//			p1CheckSelect(cuckooTable, circuitInputShare, keys);
	//		break;
	//	}
	//	case 2:
	//	{
	//		u64 selectByteCount = 0;
	//		for (auto& c : circuitInputCols)
	//			selectByteCount += c->getByteCount();

	//		// place the right table's select columns into a cuckoo table using the keys as hash values.
	//		cuckooHashSend(circuitInputCols, cuckooParams);
	//		setTimePoint("intersect_cuckoo_hash");

	//		// based on the keys for the left table, select the corresponding entries out of
	//		// the cuckoo hash table. circuitInputShare will hold three shares per left table entry, 
	//		// one share for each of the three hash function.
	//		selectCuckooPos(leftTable.rows(), cuckooParams.numBins(), selectByteCount);
	//		setTimePoint("intersect_select_cuckoo");
	//		break;
	//	}
	//	default:
	//		throw std::runtime_error("");
	//	}

	//	return circuitInputShare;
	//}


	////void OoJoin::constructOutTable(
	////	std::vector<SharedColumn*>& leftCircuitInput,
	////	std::vector<SharedColumn*>& rightCircuitInput,
	////	std::vector<SharedColumn*>& circuitOutCols,
	////	std::vector<std::array<SharedColumn*, 2>>& leftPassthroughCols,
	////	SharedTable& C,
	////	const JoinQuery& query)
	////{
	////	auto& rightTable = query.mRightKey.mTable;
	////	auto& leftTable = query.mLeftKey.mTable;
	////	auto numRows = leftTable.rows() + rightTable.rows() * query.isUnion();

	////	rightCircuitInput.reserve(rightTable.mColumns.size());
	////	leftCircuitInput.reserve(leftTable.mColumns.size());

	////	C.mColumns.resize(query.mOutputs.size() + query.isNoReveal());

	////	//if (query.isNoReveal())
	////	//{

	////		C.mColumns.back().mType = std::make_shared<IntType>(1);
	////		C.mColumns.back().mName = "isActive";
	////		C.mColumns.back().resize(numRows, C.mColumns.back().mType->getBitCount());
	////		C.mColumns.back().mShares[0].setZero();
	////		C.mColumns.back().mShares[1].setZero();
	////	//}

	////	for (u64 j = 0; j < query.mOutputs.size(); ++j)
	////	{
	////		C.mColumns[j].mType = query.mMem[query.mOutputs[j].mMemIdx].mType;
	////		C.mColumns[j].mName = query.mOutputs[j].mName;
	////		C.mColumns[j].resize(numRows, C.mColumns[j].mType->getBitCount());
	////		C.mColumns[j].mShares[0].setZero();
	////		C.mColumns[j].mShares[1].setZero();

	////		if (query.isLeftPassthrough(query.mOutputs[j]))
	////		{
	////			auto& mem = query.mMem[query.mOutputs[j].mMemIdx];
	////			leftPassthroughCols.push_back({
	////				&query.mInputs[mem.mInputIdx].mCol.mCol,
	////				&C.mColumns[j] });
	////		}
	////		else
	////		{
	////			circuitOutCols.push_back(&C.mColumns[j]);
	////		}
	////	}

	////	for (u64 j = 0; j < query.mInputs.size(); ++j)
	////	{
	////		if (query.isCircuitInput(query.mInputs[j]))
	////		{
	////			if (&query.mInputs[j].mCol.mTable == query.mRightTable)
	////				rightCircuitInput.push_back(&query.mInputs[j].mCol.mCol);
	////			else
	////				leftCircuitInput.push_back(&query.mInputs[j].mCol.mCol);
	////		}
	////	}
	////}






	//void OoJoin::cuckooHashSend(span<SharedColumn*> selects, CuckooParam& cuckooParams)
	//{
	//	if (mIdx != 2)
	//		throw std::runtime_error(LOCATION);


	//	u64 totalBytes = 0;
	//	std::vector<u64> strides(selects.size());
	//	for (u64 j = 0; j < selects.size(); ++j)
	//	{
	//		strides[j] = selects[j]->getByteCount();
	//		totalBytes += strides[j];
	//	}

	//	Matrix<u8> share1(cuckooParams.numBins(), totalBytes);

	//	//auto dest = share1.data();
	//	auto rows = selects[0]->rows();
	//	for (u32 i = 0; i < rows; ++i)
	//	{

	//		u64 h = 0;
	//		for (u64 j = 0; j < strides.size(); ++j)
	//		{
	//			auto& t = *selects[j];
	//			auto src0 = (u8*)(t.mShares[0].data() + i * t.i64Cols());
	//			auto src1 = (u8*)(t.mShares[1].data() + i * t.i64Cols());

	//			//std::cout << std::dec << " src[" << i << "] = ";

	//			for (u32 k = 0; k < strides[j]; ++k, ++h)
	//			{
	//				share1(i, h) = src0[k] ^ src1[k];
	//				//std::cout << " " << std::setw(2) << std::hex << int(share1(i, j));
	//			}
	//		}
	//		//std::cout << std::dec << std::endl;
	//	}

	//	OblvPermutation oblvPerm;
	//	oblvPerm.send(mRt.mComm.mNext, mRt.mComm.mPrev, std::move(share1), (std::to_string(mIdx)) + "_cuckoo_hash_send");

	//	//mEnc.reveal(mRt.mComm, 0, leftTable.mKeys);
	//}

	//Matrix<u8> OoJoin::cuckooHashRecv(span<SharedColumn*> selects)
	//{

	//	if (mIdx != 1)
	//		throw std::runtime_error(LOCATION);

	//	u64 totalBytes = 0;
	//	std::vector<u64> strides(selects.size());
	//	for (u64 j = 0; j < selects.size(); ++j)
	//	{
	//		strides[j] = selects[j]->getByteCount();
	//		totalBytes += strides[j];
	//	}

	//	auto rows = selects[0]->rows();
	//	auto cuckooParams = CuckooIndex<>::selectParams(rows, OoJoin_ssp, 0, 3);
	//	Matrix<u8> share1(cuckooParams.numBins(), totalBytes);

	//	share1.setZero();

	//	OblvPermutation oblvPerm;
	//	oblvPerm.recv(mRt.mComm.mPrev, mRt.mComm.mNext, share1, share1.rows(), (std::to_string(mIdx)) + "_cuckoo_hash_recv");


	//	//auto dest = share1.data();
	//	//for (u32 i = 0; i < share1.destRows(); ++i)
	//	//{
	//	//    std::cout << std::dec << " s1[" << i <<"] = ";

	//	//    for (u32 j = 0; j < share1.cols(); ++j)
	//	//    {
	//	//        std::cout << " " << std::setw(2) << std::hex<<int(share1(i,j));
	//	//    }
	//	//    std::cout << std::dec << std::endl;
	//	//}



	//	//mEnc.reveal(mRt.mComm, 0, leftTable.mKeys);

	//	//if (OoJoin_debug)
	//	//    mComm.mPrev.asyncSendCopy(share1.data(), share1.size());



	//	return (share1);
	//}

	//std::array<Matrix<u8>, 3> OoJoin::selectCuckooPos(MatrixView<u8> cuckooHashTable, u64 rows)
	//{
	//	if (mIdx != 0)
	//		throw std::runtime_error("");


	//	auto cols = cuckooHashTable.cols();
	//	std::array<Matrix<u8>, 3> dest;
	//	dest[0].resize(rows, cols, oc::AllocType::Uninitialized);
	//	dest[1].resize(rows, cols, oc::AllocType::Uninitialized);
	//	dest[2].resize(rows, cols, oc::AllocType::Uninitialized);

	//	OblvSwitchNet snet(std::to_string(mIdx));
	//	for (u64 h = 0; h < 3; ++h)
	//	{
	//		snet.sendRecv(mRt.mComm.mNext, mRt.mComm.mPrev, cuckooHashTable, dest[h]);
	//	}

	//	return (dest);
	//}

	//void OoJoin::selectCuckooPos(u64 destRows, u64 srcRows, u64 bytes)
	//{
	//	OblvSwitchNet snet(std::to_string(mIdx));
	//	for (u64 h = 0; h < 3; ++h)
	//	{
	//		snet.help(mRt.mComm.mPrev, mRt.mComm.mNext, mPrng,
	//			(destRows),
	//			(srcRows),
	//			(bytes));
	//	}
	//}

	//std::array<Matrix<u8>, 3> OoJoin::selectCuckooPos(
	//	MatrixView<u8> cuckooHashTable,
	//	u64 destRows,
	//	CuckooParam& cuckooParams,
	//	aby3::i64Matrix& keys)
	//{
	//	if (mIdx != 1)
	//		throw std::runtime_error("");

	//	//auto cuckooParams = CuckooIndex<>::selectParams(keys.rows(), OoJoin_ssp, 0, 3);
	//	auto numBins = cuckooParams.numBins();

	//	span<block> view((block*)keys.data(), keys.rows());

	//	auto cols = cuckooHashTable.cols();

	//	std::array<Matrix<u8>, 3> dest;
	//	dest[0].resize(destRows, cols, oc::AllocType::Uninitialized);
	//	dest[1].resize(destRows, cols, oc::AllocType::Uninitialized);
	//	dest[2].resize(destRows, cols, oc::AllocType::Uninitialized);
	//	//if (dest[0].cols() != cuckooHashTable.cols())
	//	//    throw std::runtime_error("");

	//	//if (dest[0].destRows() != keys.destRows())
	//	//    throw std::runtime_error("");

	//	OblvSwitchNet snet(std::to_string(mIdx));

	//	std::array<OblvSwitchNet::Program, 3> progs;
	//	for (u64 h = 0; h < 3; ++h)
	//	{
	//		progs[h].init(
	//			(cuckooHashTable.rows()),
	//			(keys.rows()));
	//	}

	//	CuckooIndex<> cuckoo;
	//	cuckoo.init(cuckooParams);
	//	for (u64 i = 0; i < view.size(); ++i)
	//	{
	//		std::array<u32, 3> hx{};
	//		cuckoo.computeLocations(span<block>(&view[i], 1), oc::MatrixView<u32>(hx.data(), 1, 3));
	//		//    CuckooIndex<>::getHash(view[i], 0, numBins),
	//		//    CuckooIndex<>::getHash(view[i], 1, numBins),
	//		//    CuckooIndex<>::getHash(view[i], 2, numBins)
	//		//};

	//	   //if ((hx[0] == hx[1] || hx[0] == hx[2] || hx[1] == hx[2]))
	//	   //{
	//	   //    if (hx[0] == hx[1])
	//	   //        hx[1] = (hx[1] + 1) % numBins;

	//	   //    if (hx[0] == hx[2] || hx[1] == hx[2])
	//	   //        hx[2] = (hx[2] + 1) % numBins;

	//	   //    if (hx[0] == hx[2] || hx[1] == hx[2])
	//	   //        hx[2] = (hx[2] + 1) % numBins;
	//	   //}

	//		for (u64 h = 0; h < 3; ++h)
	//		{


	//			progs[h].addSwitch((u32)hx[h], (u32)i);

	//			auto destPtr = &dest[h](i, 0);
	//			auto srcPtr = &cuckooHashTable(hx[h], 0);

	//			memcpy(destPtr, srcPtr, dest[h].cols());
	//		}

	//	}

	//	for (u64 h = 0; h < 3; ++h)
	//	{
	//		snet.program(mRt.mComm.mNext, mRt.mComm.mPrev, progs[h], mPrng, dest[h], OutputType::Additive);
	//	}


	//	return (dest);
	//}

	//aby3::sPackedBin OoJoin::compare(
	//	span<SharedColumn*> leftCircuitInput,
	//	span<SharedColumn*> rightCircuitInput,
	//	span<SharedColumn*> circuitOutput,
	//	const SelectQuery& query,
	//	span<Matrix<u8>> inShares)
	//{
	//	auto size = query.mLeftTable->rows();

	//	//auto bitCount = std::accumulate(outColumns.begin(), outColumns.end(), leftJoinCol.mCol.getBitCount(), [](auto iter) { return iter->->mCol.getBitCount();  });
	//	auto byteCount = 0ull;
	//	for (auto& c : rightCircuitInput)
	//		byteCount += c->getByteCount();

	//	std::array<aby3::sPackedBin, 3> A;
	//	A[0].reset(size, byteCount * 8);
	//	A[1].reset(size, byteCount * 8);
	//	A[2].reset(size, byteCount * 8);



	//	aby3::Sh3Task t0, t1, t2;
	//	if (inShares.size() && inShares[0].size())
	//	{

	//		if (A[0].shareCount() != inShares[0].rows())
	//			throw RTE_LOC;

	//		if (A[0].bitCount() != inShares[0].cols() * 8)
	//		{
	//			std::cout << A[0].bitCount() << " != " << inShares[0].cols() * 8 << std::endl;
	//			throw RTE_LOC;
	//		}

	//		t0 = mEnc.localPackedBinary(mRt.noDependencies(), inShares[0], A[0], true);
	//		t1 = mEnc.localPackedBinary(mRt.noDependencies(), inShares[1], A[1], true);
	//		t2 = mEnc.localPackedBinary(mRt.noDependencies(), inShares[2], A[2], true);
	//	}
	//	else
	//	{
	//		t0 = mEnc.remotePackedBinary(mRt.noDependencies(), A[0]);
	//		t1 = mEnc.remotePackedBinary(mRt.noDependencies(), A[1]);
	//		t2 = mEnc.remotePackedBinary(mRt.noDependencies(), A[2]);
	//	}

	//	mRt.runOneRound();
	//	auto cir = getQueryCircuit(leftCircuitInput, rightCircuitInput, circuitOutput, query);

	//	aby3::Sh3BinaryEvaluator eval;

	//	if (OoJoin_debug)
	//		eval.enableDebug(mIdx, 0, mRt.mComm.mPrev, mRt.mComm.mNext);

	//	eval.setCir(&cir, size, mEnc.mShareGen);

	//	u64 i = 0;
	//	for (; i < leftCircuitInput.size(); ++i)
	//		eval.setInput(i, *leftCircuitInput[i]);

	//	t0.get();
	//	eval.setInput(i++, A[0]);
	//	t1.get();
	//	eval.setInput(i++, A[1]);
	//	t2.get();
	//	eval.setInput(i++, A[2]);

	//	std::vector<std::vector<aby3::Sh3BinaryEvaluator::DEBUG_Triple>>plainWires;
	//	eval.distributeInputs();

	//	if (OoJoin_debug)
	//		plainWires = eval.mPlainWires_DEBUG;

	//	mRt.runAll();

	//	eval.asyncEvaluate(mRt.noDependencies()).get();

	//	aby3::sPackedBin outFlags(size, 1);
	//	eval.getOutput(0, outFlags);

	//	for (u64 i = 0; i < circuitOutput.size(); ++i)
	//		eval.getOutput(i + 1, *circuitOutput[i]);

	//	//if (OoJoin_debug)
	//	//{



	//	//    aby3::i64Matrix bb(rightJoinCol.mCol.rows(), rightJoinCol.mCol.i64Cols());
	//	//    mEnc.revealAll(mComm, rightJoinCol.mCol, bb);
	//	//    std::array<Matrix<u8>, 3> aa, select;
	//	//    aa[0].resize(inShares[0].rows(), inShares[0].cols());
	//	//    aa[1].resize(inShares[1].rows(), inShares[1].cols());
	//	//    aa[2].resize(inShares[2].rows(), inShares[2].cols());
	//	//    select[0].resize(inShares[0].rows(), inShares[0].cols());
	//	//    select[1].resize(inShares[1].rows(), inShares[1].cols());
	//	//    select[2].resize(inShares[2].rows(), inShares[2].cols());

	//	//    if (mIdx == 0)
	//	//    {
	//	//        mComm.mNext.asyncSend(inShares[0].data(), inShares[0].size());
	//	//        mComm.mNext.asyncSend(inShares[1].data(), inShares[1].size());
	//	//        mComm.mNext.asyncSend(inShares[2].data(), inShares[2].size());
	//	//        mComm.mNext.recv(aa[0].data(), aa[0].size());
	//	//        mComm.mNext.recv(aa[1].data(), aa[1].size());
	//	//        mComm.mNext.recv(aa[2].data(), aa[2].size());
	//	//    }
	//	//    else if (mIdx == 1)
	//	//    {
	//	//        mComm.mPrev.asyncSend(inShares[0].data(), inShares[0].size());
	//	//        mComm.mPrev.asyncSend(inShares[1].data(), inShares[1].size());
	//	//        mComm.mPrev.asyncSend(inShares[2].data(), inShares[2].size());
	//	//        mComm.mPrev.recv(aa[0].data(), aa[0].size());
	//	//        mComm.mPrev.recv(aa[1].data(), aa[1].size());
	//	//        mComm.mPrev.recv(aa[2].data(), aa[2].size());
	//	//    }

	//	//    std::vector<std::array<bool, 3>> exp(size);
	//	//    auto compareBytes = (leftJoinCol.mCol.getBitCount() + 7) / 8;

	//	//    if (mIdx != 2)
	//	//    {

	//	//        ostreamLock o(std::cout);

	//	//        for (auto i = 0; i < inShares[0].rows(); ++i)
	//	//        {
	//	//            for (auto j = 0; j < inShares[0].cols(); ++j)
	//	//            {
	//	//                select[0](i, j) = aa[0](i, j) ^ inShares[0](i, j);
	//	//                select[1](i, j) = aa[1](i, j) ^ inShares[1](i, j);
	//	//                select[2](i, j) = aa[2](i, j) ^ inShares[2](i, j);
	//	//            }

	//	//            if (debug_print)
	//	//                std::cout << "p " << mIdx << " select[0][" << i << "] = " << hexString(&select[0](i, 0), inShares[0].cols()) << " = " << hexString(&aa[0](i, 0), inShares[0].cols()) << " ^ " << hexString(&inShares[0](i, 0), inShares[0].cols()) << std::endl;
	//	//        }


	//	//        for (auto i = 0; i < size; ++i)
	//	//        {
	//	//            if (debug_print)
	//	//                std::cout << "select[" << mIdx << "][" << i << "] "
	//	//                << hexString(select[0][i].data(), compareBytes) << " "
	//	//                << hexString(select[1][i].data(), compareBytes) << " "
	//	//                << hexString(select[2][i].data(), compareBytes) << " vs "
	//	//                << hexString((u8*)bb.row(i).data(), compareBytes) << std::endl;;

	//	//            if (memcmp(select[0][i].data(), bb.row(i).data(), compareBytes) == 0)
	//	//                exp[i][0] = true;
	//	//            if (memcmp(select[1][i].data(), bb.row(i).data(), compareBytes) == 0)
	//	//                exp[i][1] = true;
	//	//            if (memcmp(select[2][i].data(), bb.row(i).data(), compareBytes) == 0)
	//	//                exp[i][2] = true;

	//	//            BitIterator iter0(select[0][i].data(), 0);
	//	//            BitIterator iter1(select[1][i].data(), 0);
	//	//            BitIterator iter2(select[2][i].data(), 0);

	//	//            for (u64 b = 0; b < cir.mInputs[0].size(); ++b)
	//	//            {
	//	//                if (*iter0++ != plainWires[i][cir.mInputs[1][b]].val())
	//	//                    throw RTE_LOC;
	//	//                if (*iter1++ != plainWires[i][cir.mInputs[2][b]].val())
	//	//                    throw RTE_LOC;
	//	//                if (*iter2++ != plainWires[i][cir.mInputs[3][b]].val())
	//	//                    throw RTE_LOC;
	//	//            }

	//	//        }
	//	//    }

	//	//    aby3::sPackedBin r0(outFlags.shareCount(), outFlags.bitCount());
	//	//    aby3::sPackedBin r1(outFlags.shareCount(), outFlags.bitCount());
	//	//    aby3::sPackedBin r2(outFlags.shareCount(), outFlags.bitCount());
	//	//    r0.mShares[0].setZero();
	//	//    r0.mShares[1].setZero();
	//	//    r1.mShares[0].setZero();
	//	//    r1.mShares[1].setZero();
	//	//    r2.mShares[0].setZero();
	//	//    r2.mShares[1].setZero();
	//	//    eval.getOutput(cir.mOutputs.size() - 3, r0);
	//	//    eval.getOutput(cir.mOutputs.size() - 2, r1);
	//	//    eval.getOutput(cir.mOutputs.size() - 1, r2);

	//	//    aby3::PackedBin iflag(r0.shareCount(), r0.bitCount());
	//	//    aby3::PackedBin rr0(r0.shareCount(), r0.bitCount());
	//	//    aby3::PackedBin rr1(r1.shareCount(), r1.bitCount());
	//	//    aby3::PackedBin rr2(r2.shareCount(), r2.bitCount());

	//	//    mEnc.revealAll(mRt.noDependencies(), outFlags, iflag);
	//	//    mEnc.revealAll(mRt.noDependencies(), r0, rr0);
	//	//    mEnc.revealAll(mRt.noDependencies(), r1, rr1);
	//	//    mEnc.revealAll(mRt.noDependencies(), r2, rr2).get();

	//	//    BitIterator f((u8*)iflag.mData.data(), 0);
	//	//    BitIterator i0((u8*)rr0.mData.data(), 0);
	//	//    BitIterator i1((u8*)rr1.mData.data(), 0);
	//	//    BitIterator i2((u8*)rr2.mData.data(), 0);

	//	//    if (mIdx != 2)
	//	//    {
	//	//        ostreamLock o(std::cout);
	//	//        for (u64 i = 0; i < r0.shareCount(); ++i)
	//	//        {
	//	//            u8 ff = *f++;
	//	//            u8 ii0 = *i0++;
	//	//            u8 ii1 = *i1++;
	//	//            u8 ii2 = *i2++;

	//	//            auto t0 = ii0 != exp[i][0];
	//	//            auto t1 = ii1 != exp[i][1];
	//	//            auto t2 = ii2 != exp[i][2];

	//	//            if (debug_print || t0 || t1 || t2)
	//	//                o << "circuit[" << mIdx << "][" << i << "] "
	//	//                << " b  " << hexString((u8*)bb.row(i).data(), compareBytes) << "\n"
	//	//                << " a0 " << hexString((u8*)select[0][i].data(), compareBytes) << "\n"
	//	//                << " a1 " << hexString((u8*)select[1][i].data(), compareBytes) << "\n"
	//	//                << " a2 " << hexString((u8*)select[2][i].data(), compareBytes) << "\n"
	//	//                << " -> " << int(ff) << " = (" << int(ii0) << " " << int(ii1) << " " << int(ii2) << ")" << std::endl;

	//	//            if (t0)
	//	//                throw std::runtime_error("");

	//	//            if (t1)
	//	//                throw std::runtime_error("");

	//	//            if (t2)
	//	//                throw std::runtime_error("");

	//	//        }
	//	//    }
	//	//}


	//	return (outFlags);
	//}

	//aby3::sPackedBin OoJoin::unionCompare(
	//	ColRef leftJoinCol,
	//	ColRef rightJoinCol,
	//	span<Matrix<u8>> inShares)
	//{

	//	auto size = leftJoinCol.mCol.rows();

	//	//auto bitCount = std::accumulate(outColumns.begin(), outColumns.end(), leftJoinCol.mCol.getBitCount(), [](auto iter) { return iter->->mCol.getBitCount();  });
	//	auto byteCount = leftJoinCol.mCol.getByteCount();

	//	std::array<aby3::sPackedBin, 3> A;
	//	A[0].reset(size, byteCount * 8);
	//	A[1].reset(size, byteCount * 8);
	//	A[2].reset(size, byteCount * 8);

	//	aby3::Sh3Task t0, t1, t2;
	//	if (inShares.size() && inShares[0].size())
	//	{
	//		t0 = mEnc.localPackedBinary(mRt.noDependencies(), inShares[0], A[0], true);
	//		t1 = mEnc.localPackedBinary(mRt.noDependencies(), inShares[1], A[1], true);
	//		t2 = mEnc.localPackedBinary(mRt.noDependencies(), inShares[2], A[2], true);
	//	}
	//	else
	//	{
	//		t0 = mEnc.remotePackedBinary(mRt.noDependencies(), A[0]);
	//		t1 = mEnc.remotePackedBinary(mRt.noDependencies(), A[1]);
	//		t2 = mEnc.remotePackedBinary(mRt.noDependencies(), A[2]);
	//	}

	//	mRt.runOneRound();
	//	auto cir = getBasicCompareCircuit(leftJoinCol, {});

	//	aby3::Sh3BinaryEvaluator eval;

	//	if (OoJoin_debug)
	//		eval.enableDebug(mIdx, 0, mRt.mComm.mPrev, mRt.mComm.mNext);

	//	eval.setCir(&cir, size, mEnc.mShareGen);
	//	eval.setInput(0, leftJoinCol.mCol);
	//	t0.get();
	//	eval.setInput(1, A[0]);
	//	t1.get();
	//	eval.setInput(2, A[1]);
	//	t2.get();
	//	eval.setInput(3, A[2]);

	//	std::vector<std::vector<aby3::Sh3BinaryEvaluator::DEBUG_Triple>>plainWires;
	//	eval.distributeInputs();

	//	if (OoJoin_debug)
	//		plainWires = eval.mPlainWires_DEBUG;

	//	mRt.runAll();

	//	eval.asyncEvaluate(mRt.noDependencies()).get();

	//	aby3::sPackedBin outFlags(size, 1);
	//	eval.getOutput(0, outFlags);

	//	return (outFlags);
	//}

	//aby3::i64Matrix OoJoin::computeKeys(span<ColRef> cols, span<u64> reveals)
	//{
	//	aby3::i64Matrix ret;
	//	std::vector<aby3::Sh3BinaryEvaluator> binEvals(cols.size());

	//	auto blockSize = mLowMCCir.mInputs[0].size();
	//	auto rounds = mLowMCCir.mInputs.size() - 1;

	//	aby3::sbMatrix oprfRoundKey(1, blockSize);// , temp;
	//	for (u64 i = 0; i < cols.size(); ++i)
	//	{
	//		//auto shareCount = tables[i]->mKeys.shareCount();
	//		auto shareCount = cols[i].mTable.rows();

	//		//if (i == 0)
	//		//{
	//		//    binEvals[i].enableDebug(mIdx, mPrev, mNext);
	//		//}
	//		binEvals[i].setCir(&mLowMCCir, shareCount, mEnc.mShareGen);

	//		binEvals[i].setInput(0, cols[i].mCol);
	//	}

	//	for (u64 j = 0; j < rounds; ++j)
	//	{
	//		mEnc.rand(oprfRoundKey);

	//		for (u64 i = 0; i < cols.size(); ++i)
	//		{
	//			//temp.resize(shareCount, blockSize);
	//			//for (u64 k = 0; k < shareCount; ++k)
	//			//{
	//			//    for (u64 l = 0; l < temp.mShares[0].cols(); ++l)
	//			//    {
	//			//        temp.mShares[0](k, l) = oprfRoundKey.mShares[0](0, l);
	//			//        temp.mShares[1](k, l) = oprfRoundKey.mShares[1](0, l);
	//			//    }
	//			//}
	//			//binEvals[i].setInput(j + 1, temp);
	//			binEvals[i].setReplicatedInput(j + 1, oprfRoundKey);
	//		}
	//	}

	//	for (u64 i = 0; i < cols.size(); ++i)
	//	{


	//		binEvals[i].asyncEvaluate(mRt.noDependencies());
	//	}

	//	// actaully runs the computations
	//	mRt.runAll();


	//	std::vector<aby3::sPackedBin> temps(cols.size());

	//	for (u64 i = 0; i < cols.size(); ++i)
	//	{
	//		//auto shareCount = tables[i]->mKeys.shareCount();
	//		auto shareCount = cols[i].mCol.rows();
	//		temps[i].reset(shareCount, blockSize);

	//		if (reveals[i] == mIdx)
	//		{
	//			if (ret.size())
	//				throw std::runtime_error("only one output per party. " LOCATION);
	//			ret.resize(shareCount, blockSize / 64);


	//			binEvals[i].getOutput(0, temps[i]);
	//			mEnc.reveal(mRt.noDependencies(), temps[i], ret);
	//		}
	//		else
	//		{
	//			binEvals[i].getOutput(0, temps[i]);
	//			mEnc.reveal(mRt.noDependencies(), reveals[i], temps[i]);
	//		}
	//	}

	//	// actaully perform the reveals
	//	mRt.runAll();

	//	return ret;
	//}

	//BetaCircuit OoJoin::getQueryCircuit(
	//	span<SharedColumn*> leftCircuitInput,
	//	span<SharedColumn*> rightCircuitInput,
	//	span<SharedColumn*> circuitOutput,
	//	const SelectQuery& query)
	//{
	//	BetaCircuit r;


	//	std::vector<std::pair<int, bool>> leftInputOrder(leftCircuitInput.size());
	//	std::vector<int> rightInputOrder(rightCircuitInput.size());
	//	auto leftIter = leftInputOrder.begin();
	//	auto rightIter = rightInputOrder.begin();

	//	for (u64 i = 0, j = 0; i < query.mInputs.size(); ++i)
	//	{
	//		if (query.isCircuitInput(query.mInputs[i]))
	//		{
	//			if (&query.mInputs[i].mCol.mTable == query.mLeftTable)
	//				*leftIter++ = { (int)j++, query.mMem[query.mInputs[i].mMemIdx].mUsed };
	//			else
	//				*rightIter++ = j++;
	//		}
	//	}

	//	if (leftIter != leftInputOrder.end())
	//		throw RTE_LOC;
	//	if (rightIter != rightInputOrder.end())
	//		throw RTE_LOC;





	//	u64 totalByteCount = 0;
	//	for (auto& c : rightCircuitInput)
	//		totalByteCount += c->getByteCount();
	//	BetaBundle
	//		a0(totalByteCount * 8),
	//		a1(totalByteCount * 8),
	//		a2(totalByteCount * 8),
	//		out(1);

	//	std::vector<BetaBundle>
	//		leftBundles(leftCircuitInput.size()),
	//		outputBundles(circuitOutput.size()),
	//		midBundles(leftCircuitInput.size() + rightCircuitInput.size());


	//	for (u64 i = 0; i < leftBundles.size(); ++i)
	//	{
	//		leftBundles[i].mWires.resize(leftCircuitInput[i]->getBitCount());
	//		r.addInputBundle(leftBundles[i]);
	//	}

	//	r.addInputBundle(a0);
	//	r.addInputBundle(a1);
	//	r.addInputBundle(a2);


	//	r.addOutputBundle(out);
	//	for (u64 i = 0; i < circuitOutput.size(); ++i)
	//	{
	//		outputBundles[i].mWires.resize(circuitOutput[i]->getBitCount());
	//		r.addOutputBundle(outputBundles[i]);
	//	}


	//	for (u64 i = 0; i < leftInputOrder.size(); ++i)
	//	{
	//		auto idx = leftInputOrder[i].first;
	//		auto used = leftInputOrder[i].second;

	//		if (used)
	//			midBundles[idx].mWires = leftBundles[i].mWires;
	//	}

	//	for (u64 i = 0; i < rightInputOrder.size(); ++i)
	//	{
	//		auto inputPos = rightInputOrder[i];
	//		auto input = query.mInputs[inputPos];
	//		auto& mem = query.mMem[input.mMemIdx];

	//		if (mem.isOutput())
	//		{
	//			midBundles[inputPos] =
	//				outputBundles[query.mOutputs[mem.mOutputIdx].mPosition];
	//		}
	//		else if (mem.mUsed)
	//		{
	//			midBundles[inputPos].mWires.resize(query.mInputs[inputPos].mCol.mCol.getBitCount());
	//			r.addTempWireBundle(midBundles[inputPos]);
	//		}
	//	}


	//	u64 compareBitCount = leftCircuitInput[0]->getBitCount();
	//	BetaBundle t0(compareBitCount), t1(compareBitCount), t2(compareBitCount);
	//	r.addTempWireBundle(t0);
	//	r.addTempWireBundle(t1);
	//	r.addTempWireBundle(t2);

	//	// compute a0 = a0 ^ b ^ 1
	//	// compute a1 = a1 ^ b ^ 1
	//	// compute a2 = a2 ^ b ^ 1
	//	for (auto i = 0ull; i < compareBitCount; ++i)
	//	{
	//		r.addGate(a0[i], leftBundles[0][i], GateType::Nxor, t0[i]);
	//		r.addGate(a1[i], leftBundles[0][i], GateType::Nxor, t1[i]);
	//		r.addGate(a2[i], leftBundles[0][i], GateType::Nxor, t2[i]);
	//	}

	//	// check if a0,a1, or a2 are all ones, meaning ai == b
	//	while (compareBitCount != 1)
	//	{
	//		for (u64 i = 0, j = compareBitCount - 1; i < j; ++i, --j)
	//		{
	//			r.addGate(t0[i], t0[j], GateType::And, t0[i]);
	//			r.addGate(t1[i], t1[j], GateType::And, t1[i]);
	//			r.addGate(t2[i], t2[j], GateType::And, t2[i]);
	//		}
	//		compareBitCount = (compareBitCount + 1) / 2;
	//	}


	//	// return the parity if the three eq tests. 
	//	// this will be 1 if a single items matchs. 
	//	// We should never have 2 matches so this is 
	//	// effectively the same as using GateType::Or
	//	r.addGate(t0[0], t1[0], GateType::Xor, out[0]);
	//	r.addGate(t2[0], out[0], GateType::Xor, out[0]);






	//	u64 selectStart = leftCircuitInput[0]->getBitCount();
	//	// compute the select strings by and with the match bit (t0,t1,t2) and then
	//	// XORing the results to get the select strings.
	//	//for (auto& out : midBundles)

	//	for (u64 i = 0; i < rightInputOrder.size(); ++i)
	//	{
	//		selectStart = roundUpTo(selectStart, 8);

	//		auto& bundle = midBundles[rightInputOrder[i]];

	//		for (u64 i = 0; i < bundle.size(); ++i)
	//		{
	//			// set the input string to zero if tis not a match
	//			r.addGate(a0[selectStart], t0[0], GateType::And, a0[selectStart]);
	//			r.addGate(a1[selectStart], t1[0], GateType::And, a1[selectStart]);
	//			r.addGate(a2[selectStart], t2[0], GateType::And, a2[selectStart]);

	//			// only one will be a match, therefore we can XOR the masked strings
	//			// as a way to only get the matching string, if there was one (zero otherwise).
	//			r.addGate(a0[selectStart], a1[selectStart], GateType::Xor, bundle[i]);
	//			r.addGate(a2[selectStart], bundle[i], GateType::Xor, bundle[i]);

	//			++selectStart;
	//		}
	//	}




	//	query.apply(r, midBundles, outputBundles);

	//	for (u64 i = 0; i < outputBundles.size(); ++i)
	//	{
	//		for (u64 j = 0; j < outputBundles[i].size(); ++j)
	//		{
	//			if (r.mWireFlags[outputBundles[i].mWires[j]] == BetaWireFlag::Uninitialized)
	//				throw RTE_LOC;
	//		}
	//	}

	//	return r;
	//}


	//BetaCircuit OoJoin::getBasicCompareCircuit(
	//	ColRef leftJoinCol,
	//	span<ColRef> cols)
	//{
	//	BetaCircuit r;

	//	u64 compareBitCount = leftJoinCol.mCol.getBitCount();
	//	u64 totalByteCount = leftJoinCol.mCol.getByteCount();;
	//	for (auto& c : cols)
	//		totalByteCount += c.mCol.getByteCount();

	//	u64 selectStart = compareBitCount;

	//	BetaBundle
	//		a0(totalByteCount * 8),
	//		a1(totalByteCount * 8),
	//		a2(totalByteCount * 8),
	//		b(compareBitCount);

	//	BetaBundle out(1), c0(1), c1(1), c2(1);
	//	r.addInputBundle(b);
	//	r.addInputBundle(a0);
	//	r.addInputBundle(a1);
	//	r.addInputBundle(a2);
	//	r.addOutputBundle(out);

	//	std::vector<BetaBundle> selectOut(cols.size());
	//	auto iterW = selectOut.begin();
	//	auto iterC = cols.begin();

	//	while (iterW != selectOut.end())
	//	{
	//		iterW->mWires.resize(iterC++->mCol.getBitCount());
	//		r.addOutputBundle(*iterW++);
	//	}

	//	if (OoJoin_debug)
	//	{
	//		r.addOutputBundle(c0);
	//		r.addOutputBundle(c1);
	//		r.addOutputBundle(c2);
	//	}

	//	BetaBundle t0(compareBitCount), t1(compareBitCount), t2(compareBitCount);
	//	r.addTempWireBundle(t0);
	//	r.addTempWireBundle(t1);
	//	r.addTempWireBundle(t2);

	//	// compute a0 = a0 ^ b ^ 1
	//	// compute a1 = a1 ^ b ^ 1
	//	// compute a2 = a2 ^ b ^ 1
	//	for (auto i = 0ull; i < compareBitCount; ++i)
	//	{
	//		r.addGate(a0[i], b[i], GateType::Nxor, t0[i]);
	//		r.addGate(a1[i], b[i], GateType::Nxor, t1[i]);
	//		r.addGate(a2[i], b[i], GateType::Nxor, t2[i]);
	//	}

	//	// check if a0,a1, or a2 are all ones, meaning ai == b
	//	while (compareBitCount != 1)
	//	{
	//		for (u64 i = 0, j = compareBitCount - 1; i < j; ++i, --j)
	//		{
	//			r.addGate(t0[i], t0[j], GateType::And, t0[i]);
	//			r.addGate(t1[i], t1[j], GateType::And, t1[i]);
	//			r.addGate(t2[i], t2[j], GateType::And, t2[i]);
	//		}
	//		compareBitCount = (compareBitCount + 1) / 2;
	//	}


	//	// return the parity if the three eq tests. 
	//	// this will be 1 if a single items matchs. 
	//	// We should never have 2 matches so this is 
	//	// effectively the same as using GateType::Or
	//	r.addGate(t0[0], t1[0], GateType::Xor, out[0]);
	//	r.addGate(t2[0], out[0], GateType::Xor, out[0]);


	//	// compute the select strings by and with the match bit (t0,t1,t2) and then
	//	// XORing the results to get the select strings.
	//	for (auto& out : selectOut)
	//	{

	//		selectStart = roundUpTo(selectStart, 8);

	//		for (u64 i = 0; i < out.size(); ++i)
	//		{
	//			// set the input string to zero if tis not a match
	//			r.addGate(a0[selectStart], t0[0], GateType::And, a0[selectStart]);
	//			r.addGate(a1[selectStart], t1[0], GateType::And, a1[selectStart]);
	//			r.addGate(a2[selectStart], t2[0], GateType::And, a2[selectStart]);

	//			// only one will be a match, therefore we can XOR the masked strings
	//			// as a way to only get the matching string, if there was one (zero otherwise).
	//			r.addGate(a0[selectStart], a1[selectStart], GateType::Xor, out[i]);
	//			r.addGate(a2[selectStart], out[i], GateType::Xor, out[i]);

	//			++selectStart;
	//		}
	//	}

	//	// output the match bits if we are debugging.
	//	if (OoJoin_debug)
	//	{
	//		r.addCopy(t0[0], c0[0]);
	//		r.addCopy(t1[0], c1[0]);
	//		r.addCopy(t2[0], c2[0]);
	//	}

	//	return r;
	//}


	//u64 SharedTable::rows()
	//{
	//	return mColumns.size() ? mColumns[0].rows() : 0;
	//}
}
