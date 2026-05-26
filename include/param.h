#pragma once
#include <map>
#include <vector>
#include "cryptoTools/Common/Defines.h"

const std::map<int, std::vector<oc::u64>> prefixLenMap = {
    { 16, { 0, 2 } },  { 32, { 0, 2 } },     { 64, { 0, 3 } },      { 128, { 0, 3 } },
    { 256, { 0, 4 } }, { 512, { 0, 3, 6 } }, { 1024, { 0, 3, 6 } }, { 2048, { 0, 4, 8 } },
};

const std::map<int, oc::u64> prefixNumMap = {
    { 16, 8 }, { 32, 12 }, { 64, 16 }, { 128, 24 }, { 256, 32 }, { 512, 23 }, { 1024, 31 }, { 2048, 39 },
};