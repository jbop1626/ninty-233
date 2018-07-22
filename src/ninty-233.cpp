/*
	ninty-233.cpp

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
#include "ninty-233.hpp"
#include <iomanip>
#include <random>
#include <limits>

/*
	BigUnsigned <--> GF(2^m) element conversions
*/
BigUnsigned gf2m_to_bigunsigned(const element src) {
	BigUnsigned dst = src[0];
	for (int i = 1; i < 8; ++i) {
		dst <<= 32;
		dst += src[i];
	}
	return dst;
}

void bigunsigned_to_gf2m(const BigUnsigned & src, element dst) {
	gf2m_set_zero(dst);
	BigUnsigned temp = src;
	for (int i = 7; i >= 0; --i) {
		BigUnsigned low32 = temp & 0xFFFFFFFF;
		dst[i] = low32.toUnsignedInt();
		temp >>= 32;
	}
}

/*
	SHA-1 result as big (unsigned) integer
*/
BigUnsigned sha1(uint8_t * input, int length) {
	SHA1_HASH hash;
	Sha1Context context;
	
	Sha1Initialise(&context);
	Sha1Update(&context, input, length);
#if defined(IQUE_ECC) && (IQUE_ECC == 1)
	uint8_t ique_magic[4] = { 0x06, 0x09, 0x19, 0x68 }; // iQue-specific magic
	Sha1Update(&context, &ique_magic, 4);
#endif
	Sha1Finalise(&context, &hash);
	
	BigUnsigned hash_bigint = hash.bytes[0];
	for (int i = 1; i < 20; ++i) {
		hash_bigint <<= 8;
		hash_bigint += hash.bytes[i];
	}

	return hash_bigint;
}

/*
	Generation of k, for signing
*/
BigUnsigned generate_k(const BigUnsigned & n, const BigUnsigned & hash) {
	BigUnsigned bu_temp = hash;
	element elem_temp;
	uint8_t os_temp[32];
	
	std::random_device rd;
	std::uniform_int_distribution<unsigned int> dist(1, std::numeric_limits<unsigned int>::max());
	unsigned int salt = dist(rd);
	salt = salt * dist(rd);
	bu_temp += salt;

	bigunsigned_to_gf2m(bu_temp, elem_temp);
	elem_to_os(elem_temp, os_temp);
	BigUnsigned k = sha1(os_temp, 32);
	k *= k;
	while(k >= n) {
		k /= 7;
	}
	return k;
}

/*
	ECC algorithms
*/
void ecdh(const uint8_t * private_key, const uint8_t * public_key, uint8_t * output) {
	element private_copy;
	ec_point public_copy;
	ec_point shared_secret;
	
	os_to_elem(private_key, private_copy);
	os_to_point(public_key, public_copy);
	
	ec_point_mul(private_copy, public_copy, shared_secret);
	
	point_to_os(shared_secret, output);
}

void ecdsa_sign(const BigUnsigned z, const uint8_t * private_key, element r_out, element s_out) {
	element private_copy;
	os_to_elem(private_key, private_copy);
	
	BigUnsigned r = 0;
	BigUnsigned s = 0;
	BigUnsigned n = gf2m_to_bigunsigned(G_order);
	BigUnsigned D = gf2m_to_bigunsigned(private_copy);
	
	while(r == 0 || s == 0) {
		// Generate k in [1, n - 1]
		BigUnsigned k = generate_k(n, z);
		element k_elem;
		bigunsigned_to_gf2m(k, k_elem);
		
		// Calculate P = kG
		ec_point G;
		gf2m_copy(G_x, G.x);
		gf2m_copy(G_y, G.y);
		ec_point P;
		ec_point_mul(k_elem, G, P);
		
		// Calculate r = x_p mod n
		BigUnsigned x_p = gf2m_to_bigunsigned(P.x);
		r = x_p % n;
		
		// Calculate s = k^-1(z + rD) mod n
		BigUnsigned k_inv = modinv(k, n);
		BigUnsigned med = (z + (r * D)) % n;
		s = (k_inv * med) % n;
	}
	bigunsigned_to_gf2m(r, r_out);
	bigunsigned_to_gf2m(s, s_out);
}

bool ecdsa_verify(const BigUnsigned z, const uint8_t * public_key, const element r_input, const element s_input) {
	ec_point Q, test;
	os_to_point(public_key, Q);
	element zero = { 0 };

	// If Q is the identity, Q is invalid
	if (gf2m_is_equal(Q.x, zero) && gf2m_is_equal(Q.y, zero)) {
		return false;
	}
	// If Q is not a point on the curve, Q is invalid
	if (!ec_point_on_curve(Q)) {
		return false;
	}
	// If nQ is not the identity, Q is invalid (or n is messed up)
	ec_point_mul(G_order, Q, test);
	if (!(gf2m_is_equal(test.x, zero) && gf2m_is_equal(test.y, zero))) {
		return false;
	}
	// Public key is valid, now verify signature...
	BigUnsigned r = gf2m_to_bigunsigned(r_input);
	BigUnsigned s = gf2m_to_bigunsigned(s_input);
	BigUnsigned n = gf2m_to_bigunsigned(G_order);

	// If r,s are not in [1, n - 1], sig is invalid
	if (r < 1 || r >= n) {
		return false;
	}
	if (s < 1 || s >= n) {
		return false;
	}

	// Calculate u_1 and u_2
	BigUnsigned s_inv = modinv(s, n);
	BigUnsigned u_1 = (z * s_inv) % n;
	BigUnsigned u_2 = (r * s_inv) % n;

	// Calculate P3 = u_1G + u_2Q
	element u_1_elem, u_2_elem;
	ec_point P1, P2, P3;
	ec_point G;
	gf2m_copy(G_x, G.x);
	gf2m_copy(G_y, G.y);
	bigunsigned_to_gf2m(u_1, u_1_elem);
	bigunsigned_to_gf2m(u_2, u_2_elem);

	ec_point_mul(u_1_elem, G, P1);
	ec_point_mul(u_2_elem, Q, P2);
	ec_point_add(P1, P2, P3);

	// If P3 is the identity, sig is invalid
	if (gf2m_is_equal(P3.x, zero) && gf2m_is_equal(P3.y, zero)) {
		return false;
	}
	
	// And finally, is r congruent to P3.x mod n?
	BigUnsigned x_p = gf2m_to_bigunsigned(P3.x);
	return r == (x_p % n);
}
