# Pairing-based Functional Encryption in Go (GoPFE)

[![GoPFE CI](https://github.com/WeiqiNs/GoPFE/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/GoPFE/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/GoPFE/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/GoPFE)

Functional encryption lets the holder of a key learn one function of encrypted data, such as an inner product, and
nothing else. GoPFE implements eight published pairing-based schemes in Go, six function-hiding inner-product
functional encryption (IPFE) schemes and two quadratic functional encryption (QFE) schemes, on BLS12-381 over
[gnark-crypto](https://github.com/Consensys/gnark-crypto).

```go
msk, err := opt.Setup(3)
table := group.NewDlogTable(opt.Base(), -1000, 1000)
sk, err := opt.KeyGen(msk, []int64{1, 2, 3})
ct, err := opt.Encrypt(msk, []int64{4, -5, 6})
result, ok := opt.Decrypt(table, sk, ct)
```

`result` is 12, the inner product of the two vectors, and the key reveals nothing else about the message.

## What functional encryption is for

In ordinary encryption a key decrypts everything or nothing. In functional encryption the holder of the master key
issues keys for specific functions: a key for the vector y, applied to an encryption of x, yields ⟨x, y⟩ and nothing
else about x. That is enough for weighted sums, statistics or a linear classifier over data the computing party never
sees; quadratic FE extends it to degree-2 polynomials such as xᵀFy, and a function-hiding scheme also hides y, so
neither side learns the other's vector. The inner-product schemes here are secret-key (`Encrypt` takes the master key),
the quadratic schemes public-key, and all rely on bilinear pairings, hence pairing-friendly curves such as BLS12-381.

## Highlights

- **Eight schemes from the literature**, one package each, all run through one table-driven test suite.
- **Uses every core.** Pairings, precomputation, generator multiples and matrix inversion split across `GOMAXPROCS`
  with results identical to a single core. With Ojaswi et al.'s scheme, a prepared key decrypts a length-10 inner
  product in about 1 ms, and 16 goroutines sharing one key reach about 7,700 decryptions per second.
- **Safe to share.** Keys and lookup tables never change after they are built, and CI runs every test under the race
  detector.
- **Hardened serialization.** Every key and ciphertext implements `encoding.BinaryMarshaler`, and decoding rejects
  truncated, trailing, out-of-range and off-curve input without allocating from untrusted lengths. CI also runs the
  tests as 32-bit to catch overflow.
- **100% statement coverage** in CI, with `gofmt` and `go vet`.

## Schemes

Inner-product FE, where a key for y decrypts a ciphertext of x to ⟨x, y⟩:

| Scheme | Package | Function hiding | Security | Paper |
| --- | --- | :---: | --- | --- |
| Bishop et al. | `ipfe/bjk` | weak | SXDH | [ASIACRYPT 2015](https://doi.org/10.1007/978-3-662-48797-6_20) |
| Tomida et al. | `ipfe/tao` | full | XDLIN | [ISC 2016](https://doi.org/10.1007/978-3-319-45871-7_24) |
| Kim et al. | `ipfe/kim` | full | generic group model | [SCN 2018](https://doi.org/10.1007/978-3-319-98113-0_29) |
| Lin | `ipfe/lin` | full | SXDH | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_20) |
| Kim, Kim and Seo | `ipfe/kks` | full | SXDH | [TCS 2019](https://doi.org/10.1016/j.tcs.2019.03.016) |
| Ojaswi et al. | `ipfe/opt` | full | generic group model | [CiC 2025](https://doi.org/10.62056/abe0zo-3y) |

Quadratic FE, where a key for a matrix F decrypts a ciphertext of (x, y) to xᵀFy and anyone with the public key can
encrypt:

| Scheme | Package | Security | Paper |
| --- | --- | --- | --- |
| Baltico et al. | `qfe/bcfg` | adaptive, generic group model | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_3) |
| Dufour-Sans et al. | `qfe/sgp` | generic group model | [NeurIPS 2019](https://proceedings.neurips.cc/paper_files/paper/2019/hash/9d28de8ff9bb6a3fa41fddfdc28f3bc1-Abstract.html) |

## Using it

`go get github.com/WeiqiNs/GoPFE`

- Every scheme has `Setup`, `KeyGen`, `Encrypt`, `Prepare` and `Decrypt`. `Setup`, `KeyGen` and `Encrypt` return an
  error wrapping `group.ErrShape` for a bad length or shape.
- `Decrypt` returns `false` when the result is outside the searched range. Bishop et al. and Kim et al. take the range
  directly; the others share one `group.DlogTable` built over `Base()` (Tomida et al.: `msk.Base()`).
- `Prepare(sk)` precomputes a key's pairing work once, and `Decrypt` accepts either the key or the prepared key.
- An encoding is n as a 4-byte big-endian integer, then the fields in declaration order with every length derived
  from n. Decoding errors match the sentinels in `group/encoding.go` with `errors.Is`.

## Build and test

```bash
go test -race ./...
go test -run '^$' -bench . ./test
```

## The PFE family

LibPFE, GoPFE, RustPFE and CudaPFE implement the same eight inner-product and quadratic functional encryption
schemes. LibPFE, GoPFE and RustPFE share test cases and benchmark inputs, and CudaPFE batches the schemes on CPUs
and NVIDIA GPUs.

| Repository | Language | Pairing backend | Role |
| --- | --- | --- | --- |
| [LibPFE](https://github.com/WeiqiNs/LibPFE) | C++20 | [LibRBP](https://github.com/WeiqiNs/LibRBP) | The eight schemes as header-only templates over any LibRBP curve |
| **GoPFE** (this repo) | Go | [gnark-crypto](https://github.com/Consensys/gnark-crypto) | The eight schemes on BLS12-381, parallel across `GOMAXPROCS` |
| [RustPFE](https://github.com/WeiqiNs/RustPFE) | Rust, Python | [arkworks](https://github.com/arkworks-rs/algebra) | The eight schemes in safe Rust over any arkworks pairing curve, with a PyO3 Python binding |
| [CudaPFE](https://github.com/WeiqiNs/CudaPFE) | C++20, CUDA | Own BLS12-381 arithmetic on [sppark](https://github.com/supranational/sppark) fields | The eight schemes batched on a CPU or NVIDIA GPU engine |
