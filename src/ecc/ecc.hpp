/*
	ecc.hpp - definitions required for ECC operations using keys
			  defined with sect233r1 / NIST B-233
	
	Copyright © 2018 Jbop (https://github.com/jbop1626);
	Modification of a part of iQueCrypt
	(https://github.com/jbop1626/iquecrypt)

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
#ifndef NINTY_233_ECC_HPP
#define NINTY_233_ECC_HPP

typedef uint32_t element[8];

typedef struct {
	element x;
	element y;
} ec_point;

/*
	sect233r1 - domain parameters over GF(2^m). Defined in SEC 2 v2.0, pp. 19-20
	Not all are currently used.
*/
const element poly_f = 	{0x0200, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000400, 0x00000000, 0x00000001};
const element poly_r = 	{0x0000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000400, 0x00000000, 0x00000001};
const element a_coeff =	{0x0000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001};
const element b_coeff =	{0x0066, 0x647EDE6C, 0x332C7F8C, 0x0923BB58, 0x213B333B, 0x20E9CE42, 0x81FE115F, 0x7D8F90AD};
const element G_x =		{0x00FA, 0xC9DFCBAC, 0x8313BB21, 0x39F1BB75, 0x5FEF65BC, 0x391F8B36, 0xF8F8EB73, 0x71FD558B};
const element G_y = 		{0x0100, 0x6A08A419, 0x03350678, 0xE58528BE, 0xBF8A0BEF, 0xF867A7CA, 0x36716F7E, 0x01F81052};
const element G_order = 	{0x0100, 0x00000000, 0x00000000, 0x00000000, 0x0013E974, 0xE72F8A69, 0x22031D26, 0x03CFE0D7}; /*
const uint32_t cofactor = 	0x02; */

/*
	Printing
*/
void print_element(const element a);
void print_point(const ec_point & a);

/*
	Helper functions for working with elements in GF(2^m)
*/
bool gf2m_is_equal(const element a, const element b);
void gf2m_set_zero(element a);
void gf2m_copy(const element src, element dst);
int  gf2m_get_bit(const element a, int index);
void gf2m_left_shift(element a, int shift);
bool gf2m_is_one(const element a);
int  gf2m_degree(const element a);
void gf2m_swap(element a, element b);

/*
	Arithmetic operations on elements in GF(2^m)
*/
void gf2m_add(const element a, const element b, element c);
void gf2m_inv(const element a, element c);
void gf2m_mul(const element a, const element b, element c);
void gf2m_div(const element a, const element b, element c);
// void gf2m_reduce(element c);
// void gf2m_square(const element a, element c);

/*
	Operations on points on the elliptic curve
	y^2 + xy = x^3 + ax^2 + b over GF(2^m)
*/
void ec_point_copy(const ec_point & src, ec_point & dst);
bool ec_point_is_equal(const ec_point & a, const ec_point & c);
void ec_point_neg(const ec_point & a, ec_point & c);
void ec_point_double(const ec_point & a, ec_point & c);
void ec_point_add(const ec_point & a, const ec_point & b, ec_point & c);
void ec_point_mul(const element a, const ec_point & b, ec_point & c);
bool ec_point_on_curve(const ec_point & a);

/*
	I/O Helpers
*/
void os_to_elem(const uint8_t * os, element elem);
void os_to_point(const uint8_t * os, ec_point & point);
void elem_to_os(const element src, uint8_t * output_os);
void point_to_os(const ec_point & src, uint8_t * output_os);

#endif
