#include "CSVParser_Test.h"
#include"cryptoTools/Common/TestCollection.h"
#include "secure-join/config.h"
#include "secure-join/Join/Table.h"

using namespace secJoin;

void table_csvIo_test()
{
	Table table;
    u64 rows = 10;
	std::vector<ColumnInfo> colsInfo = { 
        ColumnInfo("a", ColumnType::Int, 16),
        ColumnInfo("s", ColumnType::String, 64),
        ColumnInfo("b", ColumnType::Boolean, 1),
        ColumnInfo("n", ColumnType::Bin, 64)
    };
    table.init(rows, colsInfo);

    PRNG prng(block(324234, 1234213));
    prng.get<u8>(table.mColumns[0].mData);
    prng.get<u8>(table.mColumns[3].mData);
    for (auto& bb : table.mColumns[1].mData)
    {
        bb = 'a' + prng.get<u8>() % 26;
        if ((u64)&bb % 7 == 0)
            bb = ' ';
    }
    for (auto& bb : table.mColumns[2].mData)
        bb = prng.getBit();

	for (auto i = 0ull; i < table.mColumns[1].mData.size(); ++i)
    {
		if (table.mColumns[1].mData(i) == 0 || table.mColumns[1].mData(i) == ';')
			table.mColumns[1].mData(i) = 'a';
	}

	std::stringstream stream;
    table.writeCSV(stream);

    auto str = stream.str();
    //std::cout << str << std::endl;

    stream = std::stringstream(str);
    Table table2;
    table2.readCSV(stream);

    if (table != table2)
    {
        std::cout << "in\n" << table << std::endl;
        std::cout << "out\n" << table2 << std::endl;
		throw RTE_LOC;
    }

}


void table_binIo_test()
{

    Table table;
    u64 rows = 10;
    std::vector<ColumnInfo> colsInfo = {
        ColumnInfo("a", ColumnType::Int, 16),
        ColumnInfo("s", ColumnType::String, 64),
        ColumnInfo("b", ColumnType::Boolean, 1),
        ColumnInfo("n", ColumnType::Bin, 64)
    };
    table.init(rows, colsInfo);

    PRNG prng(block(324234, 1234213));
    prng.get<u8>(table.mColumns[0].mData);
    prng.get<u8>(table.mColumns[3].mData);
    for (auto& bb : table.mColumns[1].mData)
    {
        bb = 'a' + prng.get<u8>() % 26;
        if ((u64)&bb % 7 == 0)
            bb = ' ';
    }
    for (auto& bb : table.mColumns[2].mData)
        bb = prng.getBit();


    std::stringstream stream;
    table.writeBin(stream);

	auto str = stream.str();
	//std::cout << str << std::endl;
    stream = std::stringstream(str);
    Table table2;
    table2.readBin(stream);

    if (table != table2)
    {
		std::cout << "in\n" << table << std::endl;
		std::cout << "out\n" << table2 << std::endl;
		throw RTE_LOC;
	}
}