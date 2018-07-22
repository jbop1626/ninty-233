### ninty-233

ninty-233 is a library for [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) operations using sect233r1 / NIST B-233, the curve used in the [iQue Player](https://en.wikipedia.org/wiki/IQue_Player) and [Nintendo Wii](https://en.wikipedia.org/wiki/Wii).  

It can be used for [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) (used to create some encryption keys on the iQue Player) and [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) signing/verification (used to sign game saves on both consoles and to sign recrypt.sys on the iQue Player).  

Arbitrary-precision arithmetic is done using the public domain [C++ Big Integer Library](https://mattmccutchen.net/bigint/) by Matt McCutchen.  

SHA1 implementation is from the public domain [WjCryptLib](https://github.com/WaterJuice/WjCryptLib) by [WaterJuice](https://github.com/WaterJuice).  
