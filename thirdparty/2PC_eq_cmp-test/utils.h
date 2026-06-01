#pragma once
#include <stdint.h>
#include <math.h>
#include "cryptoTools/Common/BitVector.h"
#include "coproto/Socket/AsioSocket.h"
#include <cryptoTools/Network/Channel.h>

enum class Role {
    Sender,
    Receiver
};

static inline uint32_t log2(uint32_t x) {
	uint32_t y;
	asm ( "\tbsr %1, %0\n"
		: "=r"(y)
		: "r" (x)
	);
	// return x == (1 << y) ? y : y + 1;
	return y;
}

// static inline uint32_t log2(uint32_t x) {
// 	if (x == 0) return -1;
//     return std::bit_width(x - 1);
// }

int getmod(int num);

void shift(osuCrypto::BitVector &bits, int pos, int n);

coproto::task<> sync(coproto::Socket& chl, Role role);

// template<T>
// if want more than 128, should make template to input uint16_t or larger.
struct Zp {
	uint8_t value;
	static uint8_t p;
	Zp operator+(const Zp& b) const {
		return Zp{ (uint8_t)((value + b.value) % p) };
	}
	Zp operator-(const Zp& b) const {
		return Zp{ (uint8_t)((value + p - b.value) % p) };
	}
	Zp operator*(const Zp& b) const {
		return Zp{ (uint8_t)(((uint16_t)value * (uint16_t)b.value) % p) };
	}
	bool operator==(const Zp& b) const {
		return value == b.value;
	}
	bool operator!=(const Zp& b) const {
		return value != b.value;
	}
	Zp& operator=(const Zp& b) = default;
};

inline std::ostream& operator<<(std::ostream& os, const Zp& obj) {
	os << static_cast<int>(obj.value); 
	return os;
};
