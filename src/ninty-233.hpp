/*
	ninty-233
	Library for ECC operations using keys defined with
	sect233r1 / NIST B-233 -- the curve/domain parameters
	used by Nintendo in the iQue Player and Wii.

	Copyright © 2018 Jbop (https://github.com/jbop1626);

	This file is a part of ninty-233.

	ninty-233 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	ninty-233 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef NINTY_233
#define NINTY_233

#include "bigint/include/BigIntegerLibrary.hpp"
#include "ecc/ecc.hpp"
#include "sha1/sha1.hpp"

#define IQUE_ECC 1

/*
	BigUnsigned <--> GF(2^m) element conversions
*/
BigUnsigned gf2m_to_bigunsigned(const element src);
void bigunsigned_to_gf2m(const BigUnsigned & src, element dst);

/*
	SHA-1 result as big (unsigned) integer
*/
BigUnsigned sha1(uint8_t * input, int length);

/*
	Generation of k, for signing
*/
BigUnsigned generate_k(const BigUnsigned & n, const BigUnsigned & hash);

/*
	ECC algorithms
*/
void ecdh(const uint8_t * private_key, const uint8_t * public_key, uint8_t * output);
void ecdsa_sign(const BigUnsigned hash, const uint8_t * private_key, element r_out, element s_out);
bool ecdsa_verify(const BigUnsigned hash, const uint8_t * public_key, const element r_input, const element s_input);

#endif
