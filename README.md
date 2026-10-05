# Pairing-based Functional Encryption in Go (GoPFE)

[![GoPFE CI](https://github.com/WeiqiNs/GoPFE/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/GoPFE/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/GoPFE/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/GoPFE)

**GoPFE** is a Go library of pairing-based functional encryption on BLS12-381: private-key *function-hiding*
inner-product functional encryption (IPFE) and public-key quadratic functional encryption (QFE). It is the Go
counterpart of [LibPFE](https://github.com/WeiqiNs/LibPFE), with the same constructions and the same tests, and it
builds on [gnark-crypto](https://github.com/Consensys/gnark-crypto).

## Supported schemes

### Inner-product FE

A key for y decrypts a ciphertext of x to the inner product ⟨x, y⟩.

| Scheme | Package | Function hiding | Security | Ciphertext | Fixed-base `Decrypt` | Reference |
| --- | --- | :---: | --- | :---: | :---: | --- |
| Bishop et al. | `ipfe/bjk` | weak | SXDH | 2n + 6 | no | [ASIACRYPT 2015](https://doi.org/10.1007/978-3-662-48797-6_20) |
| Tomida et al. | `ipfe/tao` | full | XDLIN | 2n + 5 | yes | [ISC 2016](https://doi.org/10.1007/978-3-319-45871-7_24) |
| Kim et al. | `ipfe/kim` | full | SIM, generic group model | n + 1 | no | [SCN 2018](https://doi.org/10.1007/978-3-319-98113-0_29) |
| Lin | `ipfe/lin` | full | SXDH | 2n + 2 | yes | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_20) |
| Kim, Kim and Seo | `ipfe/kks` | full | SXDH | 2n + 8 | yes | [TCS 2019](https://doi.org/10.1016/j.tcs.2019.03.016) |
| Ojaswi et al. | `ipfe/opt` | full | SIM, generic group model | n + 4 | yes | [CiC 2025](https://doi.org/10.62056/abe0zo-3y) |

For vectors of length n, a ciphertext has the listed number of G1 elements and a key the same number of G2 elements.
Lin's scheme is the paper's weakly function-hiding scheme, lifted to full function hiding as the paper describes.

### Quadratic FE

A key for an n × n matrix F decrypts a ciphertext of (x, y) to xᵀFy. Anyone with the public key can encrypt.

| Scheme | Package | Security | Ciphertext | Key | Reference |
| --- | --- | --- | :---: | :---: | --- |
| Baltico et al. | `qfe/bcfg` | adaptive, generic group model | 2n G1 + (2n + 2) G2 | (n + 2) G1 + n G2 | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_3) |
| Dufour-Sans et al. | `qfe/sgp` | generic group model | (2n + 1) G1 + 2n G2 | 1 G2 | [NeurIPS 2019](https://proceedings.neurips.cc/paper_files/paper/2019/hash/9d28de8ff9bb6a3fa41fddfdc28f3bc1-Abstract.html) |

Both decrypt against a fixed base, and keys also carry F. A Baltico et al. key also carries the products of F with the
master key that decryption would otherwise derive from the public key. Dufour-Sans et al.'s scheme appears in the
NeurIPS paper by Ryffel, Dufour-Sans, Gay, Bach and Pointcheval.

## Usage

```go
msk := opt.Setup(3)
table := group.NewDlogTable(opt.Base(), -1000, 1000)
sk, err := opt.KeyGen(msk, []int64{1, 2, 3})
ct, err := opt.Encrypt(msk, []int64{4, -5, 6})
result, ok := opt.Decrypt(table, sk, ct)
```

```go
pk, msk := sgp.Setup(2)
table := group.NewDlogTable(sgp.Base(), -1000, 1000)
sk, err := sgp.KeyGen(msk, [][]int64{{1, 2}, {0, -1}})
ct, err := sgp.Encrypt(pk, []int64{3, 4}, []int64{5, -6})
result, ok := sgp.Decrypt(table, sk, ct)
```

`KeyGen` and `Encrypt` return an error wrapping `group.ErrShape` when an input has the wrong length or shape.
`Decrypt` returns the result and `true`, or `false` when it falls outside the searched range. Schemes with a
fixed-base `Decrypt` take a `group.DlogTable` built once for a range (over `msk.Base` for Tomida et al. and `Base()`
for the others) and reused across decryptions; Bishop et al. and Kim et al. derive the base from each key and
ciphertext, so their `Decrypt` takes the bounds instead.

`DecryptMany` takes the same arguments as `Decrypt` but a slice of ciphertexts, and returns a `group.Decryption` per
ciphertext. It precomputes the key's G2 side of the pairing once and reuses it, so decrypting many ciphertexts under one
key costs less per ciphertext than calling `Decrypt` for each. Precomputing costs nearly as much as a decryption, so
`Decrypt` stays the faster choice for a single ciphertext.

The `group` package wraps gnark-crypto's BLS12-381 with the operations the schemes need: `Zp`, `G1`, `G2` and `GT`,
vectors and matrices over Zp, multi-scalar multiplication, multi-pairings and baby-step giant-step discrete logarithms.

## Benchmarks

`test/bench_test.go` times every scheme with the same input sizes and bounds as LibPFE's benchmark and checks each
decryption against the true result before timing it. Run it with `go test -run '^$' -bench . ./test`.

The numbers below are milliseconds per operation, measured with Go 1.27 and gnark-crypto v0.22 on an AMD Ryzen 7
9800X3D. Inputs are random vectors (and matrices) whose results lie in [0, 10000]. Fixed-base schemes reuse one
discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al. search the range on every decryption.
"Dec, reused key" is `DecryptMany` over 10 ciphertexts, divided by 10.

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.65 | 0.88 | 0.52 | 3.87 | 2.88 |
| Tomida et al. | 1.10 | 0.62 | 0.35 | 2.81 | 2.01 |
| Kim et al. | 0.07 | 0.43 | 0.25 | 2.28 | 1.85 |
| Lin | 0.01 | 0.64 | 0.37 | 2.56 | 1.82 |
| Kim, Kim and Seo | 0.01 | 0.70 | 0.38 | 3.13 | 2.25 |
| Ojaswi et al. | 0.02 | 0.61 | 0.35 | 1.74 | 1.25 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 319.83 | 6.13 | 3.33 | 22.41 | 15.89 |
| Tomida et al. | 347.54 | 5.54 | 3.12 | 21.05 | 15.06 |
| Kim et al. | 38.84 | 2.66 | 1.37 | 11.67 | 8.60 |
| Lin | 0.05 | 4.52 | 2.18 | 21.43 | 15.54 |
| Kim, Kim and Seo | 0.09 | 4.50 | 2.15 | 21.37 | 15.37 |
| Ojaswi et al. | 0.04 | 2.20 | 1.08 | 10.82 | 7.97 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.63 | 0.64 | 4.13 | 4.59 | 4.23 |
| Dufour-Sans et al. | 0.54 | 0.10 | 4.11 | 4.11 | 4.14 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 3.58 | 4.10 | 35.37 | 41.58 | 37.60 |
| Dufour-Sans et al. | 3.45 | 0.46 | 36.03 | 39.65 | 39.84 |

## Testing

```bash
go test ./...
go test -coverpkg=./... -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

`test/` runs the same cases against every scheme, and CI requires 100% statement coverage.
