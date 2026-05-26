#pragma once
#include "secure-join/Defines.h"

namespace secJoin
{

	template<typename T>
	struct MatrixSequence
	{
		std::vector<oc::MatrixView<T>> mSequence;
	};
}