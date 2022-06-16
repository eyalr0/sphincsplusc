## SPHINCS+C

This repository contains the software for the [SPHINCS+C scheme](https://eprint.iacr.org/2022/778/).

It is based on the [SPHINCS+ submission repository](https://github.com/sphincs/sphincsplus) that contains the software that accompanies the [SPHINCS+ submission](https://sphincs.org/) to [NIST's Post-Quantum Cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography) project.

Currently, only the reference implementation for shake is supported.

![][test-ref]
 <!--- ![][test-sha256-avx2]
![][test-shake256-avx2]
![][test-haraka-aesni] --->

### Parameters

The [SPHINCS+C scheme](https://eprint.iacr.org/TBD) presents several novel methods for further compressing the signature size of SPHICS+ while requiring negligible added computational costs for the signer and faster verification time. Like SPHINCS+, we present named instances for specific hash functions and concrete parameters for the security level, tree dimensions, WOTS+C, and FORS+C. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e., `hash_haraka.c`, `hash_sha2.c` and `hash_shake.c`, as well as different implementations of `thash.h`, i.e., `*_robust.c` and `*_simple.c`. This is demonstrated in the `Makefile`. Note that only variants based on the reference SHAKE implementation are currently supported. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3, and 5; each category has a parameter set geared towards either small signatures or fast signature generation. 

|        | n | h | d | log(t) | k | w | log(t') | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -----: | -: | --: | ------: | -----------: | -------: | -------: | --------: |
| SPHINCS+-128s | 16 | 66 | 11 |   13 | 9 | 128 |   18 |     128 |    32 |    64 |   6,304 |
| SPHINCS+-128f | 16 | 63 | 21 |   9 | 19 | 16 |    8 |     128 |    32 |    64 |  14,904 |
| SPHINCS+-192s | 24 | 66 | 11 |   15 | 13 | 128 |   12 |     192 |    48 |    96 |  13,776 |
| SPHINCS+-192f | 24 | 66 | 22 |   9 | 25 | 16 |   13 |     192 |    48 |    96 |  33,044 |
| SPHINCS+-256s | 32 | 66 | 11 |   14 | 19 | 64 |   19 |     256 |    64 |   128 |  26,096 |
| SPHINCS+-256f | 32 | 64 | 16 |   10 | 33 | 16 |   10 |     256 |    64 |   128 |  46,884 |


### License

Following the original code from the [SPHINCS+ submission repository](https://github.com/sphincs/sphincsplus), all included code is available under the CC0 1.0 Universal Public Domain Dedication, with the exception of `rng.c`, `rng.h` and `PQCgenKAT_sign.c`, which were provided by NIST.

### Acknowledgments

We thank [Ofek Bransky](https://github.com/crossingfingers) for his contribution to the implementation and benchmark of the code.

[test-ref]: https://github.com/sphincs/sphincsplus/actions/workflows/test-ref.yml/badge.svg
 <!--- [test-sha256-avx2]: https://github.com/sphincs/sphincsplus/actions/workflows/test-sha256-avx2.yml/badge.svg
[test-shake256-avx2]: https://github.com/sphincs/sphincsplus/actions/workflows/test-shake256-avx2.yml/badge.svg
[test-haraka-aesni]: https://github.com/sphincs/sphincsplus/actions/workflows/test-haraka-aesni.yml/badge.svg --->
