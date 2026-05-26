#pragma once
#include "secure-join/CorGenerator/Request.h"
#include "secure-join/CorGenerator/TritOtBatch.h"
#include "secure-join/CorGenerator/CorGenerator.h"

namespace secJoin
{
	
	// Protocol for converting F2 secret sharing into an F3 sharing.
	// It consumes one Trit OT per bit converted.
	class ConvertToF3Sender
	{
	public:
		Request<TritOtSend> mRequest;

		// n is the number of F2 shares that will be converted/
		void init(u64 n, CorGenerator& gen)
		{
			mRequest = gen.request<TritOtSend>(n);
		}

		// start the preprocessing.
		void preprocess()
		{
			mRequest.start();
		}

		// convert F2 sharing x into F3 sharing (y1,y0).
		// y1 is the MSB and y0 is the LSB.
		macoro::task<> convert(
			span<const block> x,
			coproto::Socket& sock,
			span<block> y1, span<block> y0);
	};



	// Protocol for converting F2 secret sharing into an F3 sharing.
	// It consumes one Trit OT per bit converted.
	class ConvertToF3Recver
	{
	public:
		Request<TritOtRecv> mRequest;

		// n is the number of F2 shares that will be converted/
		void init(u64 n, CorGenerator& gen)
		{
			mRequest = gen.request<TritOtRecv>(n);
		}

		// start the preprocessing.
		void preprocess()
		{
			mRequest.start();
		}

		// convert F2 sharing x into F3 sharing (y1,y0).
		// y1 is the MSB and y0 is the LSB.
		macoro::task<> convert(
			span<const block> x,
			coproto::Socket& sock,
			span<block> y1, span<block> y0);

	};
}