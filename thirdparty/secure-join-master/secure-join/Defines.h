#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include "macoro/result.h"
#include "coproto/Common/TypeTraits.h"
#include <ranges>

namespace secJoin
{

    namespace stdr = std::ranges;
    namespace stdv = std::views;

    using u8  = oc::u8;
    using u16 = oc::u16;
    using u32 = oc::u32;
    using u64 = oc::u64;

    using i8  = oc::i8;
    using i16 = oc::i16;
    using i32 = oc::i32;
    using i64 = oc::i64;

    template<typename T> using span = oc::span<T>;




    inline u64 divCeil(u64 x, u64 y)
    {
        return (x + y - 1) / y;
    }

    inline bool getSign(span<u8> val, u64 index)
    {
        u64 i = index >> 3;
        u64 o = index & 7;
        return (val[i] >> o) & 1 ;
    }

    inline void fillInplace(span<u8> val, u64 index, bool bit)
    {
        u64 i = index >> 3;
        u64 o = index & 7;

        if (o)
        {
            u8 mask = ~u8(0) << (o + 1);
            val[i] = 
                ((bit) * (val[i] | mask)) |
                ((!bit) * (val[i] & ~mask));
            ++i;
        }

        for (; i < val.size(); ++i)
        {
            val[i] = bit * -1;
        }
    }
        


    //template<typename T>
    inline i64 signExtend(i64 val, u64 bit)
    {
        using T = i64;
        bool sign = val & (T(1) << bit);

        T mask = ~T(0) << (bit + 1);

        return
            ((sign) * (val | mask)) |
            ((!sign) * (val & ~mask));
    }

    using block = oc::block;
    using PRNG = oc::PRNG;




	template<class Container, typename = void>
	struct is_container : coproto::false_type
	{};

	template<class Container>
	struct is_container < Container, coproto::void_t <
		coproto::enable_if_t<coproto::has_data_member_func<typename std::remove_reference<Container>::type>::value>,
		coproto::enable_if_t<coproto::has_size_member_func<typename std::remove_reference<Container>::type>::value>
		>> :
		coproto::true_type {};

    inline std::string hex(oc::span<const u8> d)
    {
        std::stringstream ss;
        // for (u64 i = d.size() - 1; i < d.size(); --i)
        for (u64 i = 0; i < d.size(); i++)
            ss << std::hex << std::setw(2) << std::setfill('0') << int(d[i]);
        return ss.str();
    }
    inline std::string hex(u8 const* d, u64 s)
    {
        return hex(span<const u8>(d, s));
    }

    template<typename T>
    std::string whatError(macoro::result<T>& r)
    {
        try {
            std::rethrow_exception(r.error());
        }
        catch (std::exception& e)
        {
            return e.what();
        }
    }


}