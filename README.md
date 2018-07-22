### ninty-233

ninty-233 is a library for [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) operations using sect233r1 / NIST B-233, the curve used in the iQue Player and Nintendo Wii.  

It can be used for ECDH (used to create some encryption keys on the iQue Player) and ECDSA signing/verification (used to sign game saves on both consoles and to sign recrypt.sys on the iQue Player).  

Arbitrary-precision arithmetic is done using the public domain [C++ Big Integer Library](https://mattmccutchen.net/bigint/) by Matt McCutchen.  

SHA1 implementation is from the public domain [WjCryptLib](https://github.com/WaterJuice/WjCryptLib) by [WaterJuice](https://github.com/WaterJuice).  
