#pragma once

#include "cryptoTools/Common/CLP.h"

using namespace oc;

void LocalMapPrefix(std::vector<std::vector<u64>> &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta);

void fuzzyPsiPrefix(const oc::CLP &cmd);

void fuzzyPsiLpPrefix(const oc::CLP &cmd);