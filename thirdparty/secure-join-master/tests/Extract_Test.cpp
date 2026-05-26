#include "Extract_Test.h"
#include "secure-join/TableOps/Extract.h"
#include "secure-join/Join/Table.h"

using namespace secJoin;
void Extract_extract_Test(const oc::CLP& cmd)
{
	u64 n = cmd.getOr("n", 10);

	PRNG prng(oc::toBlock(0, 0));

	Table table(n, {
		ColumnInfo("name0", ColumnType::Int, 32),
		ColumnInfo("name1", ColumnType::Bin, 16),
		});

	for (u64 i = 0; i < table.mColumns.size(); ++i)
	{
		prng.get<u8>(table.mColumns[i].mData);
	}
	table.mIsActive.resize(n);
	for (u64 i = 0; i < n; ++i)
	{
		table.mIsActive[i] = prng.getBit();
	}

	auto shares = table.share(prng);
	auto sock = coproto::LocalAsyncSocket::makePair();
	std::array<Extract, 2> extract;
	std::array<CorGenerator, 2> gen;
	gen[0].init(sock[0].fork(), prng, 0, 10, 1 << 18, true);
	gen[1].init(sock[1].fork(), prng, 1, 10, 1 << 18, true);

	std::array<std::vector<ColumnInfo>, 2> cols
	{
		shares[0].getColumnInfo(),
		shares[1].getColumnInfo()
	};

	extract[0].init(n, cols[0], gen[0]);
	extract[1].init(n, cols[1], gen[1]);

	auto r = macoro::sync_wait(macoro::when_all_ready(
		extract[0].apply(shares[0], shares[0], sock[0], prng),
		extract[1].apply(shares[1], shares[1], sock[1], prng),
		gen[0].start(),
		gen[1].start()
	));

	std::get<0>(r).result();
	std::get<0>(r).result();

	auto res = reveal(shares[0], shares[1]);
	auto exp = table; 
	//std::cout << "\n\nres " << res << std::endl;

	res.sort();
	exp.extractActive();
	exp.sort();

	if (res!= exp)
	{
		std::cout << "table " << table << std::endl;
		std::cout << "\n\nexp " << exp << std::endl;
		std::cout << "\n\nres " << res << std::endl;
		throw RTE_LOC;
	}
}
