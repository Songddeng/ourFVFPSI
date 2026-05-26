#pragma once
#include "secure-join/Defines.h"
#include "cryptoTools/Common/MatrixView.h"

namespace secJoin
{
	template<typename T, typename Cont>
	span<T> asSpan(Cont&& c)
	{
		if (c.size() * sizeof(*c.data()) % sizeof(T))
			throw RTE_LOC;

		return span<T>((T*)c.data(), c.size() * sizeof(*c.data()) / sizeof(T));
	}

	bool areEqualImpl(
		span<u8> a,
		span<u8> b,
		u64 bitCount);

	template<typename T>
	bool areEqual(
		const span<T>& a,
		const span<T>& b,
		u64 bitCount)
	{
		return areEqualImpl(osuCrypto::asSpan<u8>(a), osuCrypto::asSpan<u8>(b), bitCount);
	}

	bool areEqualImpl(
		oc::MatrixView<u8> a,
		oc::MatrixView<u8> b,
		u64 bitCount);

	template<typename T>
	bool areEqual(
		const oc::MatrixView<T>& a,
		const oc::MatrixView<T>& b,
		u64 bitCount)
	{
		oc::MatrixView<u8> aa;
		oc::MatrixView<u8> bb;

		static_assert(std::is_trivial<T>::value, "");
		aa = oc::MatrixView<u8>((u8*)a.data(), a.rows(), a.cols() * sizeof(T));
		bb = oc::MatrixView<u8>((u8*)b.data(), b.rows(), b.cols() * sizeof(T));

		return areEqualImpl(aa, bb, bitCount);
	}

	void trimImpl(oc::MatrixView<u8> a, u64 bits);
	template<typename T>
	void trim(oc::MatrixView<T> a, i64 bits)
	{
		static_assert(std::is_trivial<T>::value, "");
		oc::MatrixView<u8> aa((u8*)a.data(), a.rows(), a.cols() * sizeof(T));
		trimImpl(aa, bits);
	}
	inline void trimSpan(oc::span<u8> a, u64 bits)
	{
		trim<u8>(oc::MatrixView<u8>(a.data(), 1, a.size()), bits);
	}
}