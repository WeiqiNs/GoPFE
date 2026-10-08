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
prepared := opt.Prepare(sk)
sameResult, ok := opt.Decrypt(table, prepared, ct)
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

Every scheme also has `Prepare(sk)`, which precomputes the key's pairing lines once (gnark-crypto's `PrecomputeLines`)
and returns a `PreparedKey`. `Decrypt` accepts either a `Key` or a `PreparedKey`, the two types its `DecryptionKey`
constraint lists, and returns the same result for both. An IPFE key is all of its decryption's G2 side, so its prepared
`Decrypt` costs about three fifths to three quarters of `Decrypt` with the key; prepare a key that will decrypt many
ciphertexts. A QFE decryption also pairs the ciphertext's own G2 points, which no key can prepare, so a prepared Baltico
et al. key saves less, and a prepared Dufour-Sans et al. key, which fixes one G2 point, decrypts in about the time of
the plain key. A prepared key holds about 24 KB per G2 point.

The `group` package wraps gnark-crypto's BLS12-381 with the operations the schemes need: `Zp`, `G1`, `G2` and `GT`,
vectors and matrices over Zp, multi-scalar multiplication, multi-pairings and baby-step giant-step discrete logarithms.
Multiples of the G1 and G2 generators come from fixed-base tables built on first use and run on one core, unlike
gnark-crypto's batch scalar multiplication, which spreads a large vector across cores.

## Benchmarks

`test/bench_test.go` times every scheme with the same input sizes and bounds as LibPFE's benchmark and checks each
decryption against the true result before timing it. Run it with `go test -run '^$' -bench . ./test`.

The numbers below are milliseconds per operation on one core (`taskset -c 2` and `-cpu 1`), measured with Go 1.27 and
gnark-crypto v0.22 on an AMD Ryzen 7 9800X3D. Inputs are random vectors (and matrices) whose results lie in [0, 10000].
Fixed-base schemes reuse one discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al. search the
range on every decryption. Prepare is the one-time cost of `Prepare(sk)`, and Prepared Dec decrypts with the prepared
key.

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.65 | 0.56 | 0.28 | 3.80 | 2.29 | 2.60 |
| Tomida et al. | 1.13 | 0.53 | 0.26 | 2.90 | 2.20 | 1.75 |
| Kim et al. | 0.07 | 0.24 | 0.12 | 2.22 | 0.94 | 1.72 |
| Lin | 0.01 | 0.46 | 0.22 | 2.59 | 1.94 | 1.57 |
| Kim, Kim and Seo | 0.01 | 0.58 | 0.28 | 3.22 | 2.58 | 1.96 |
| Ojaswi et al. | 0.01 | 0.30 | 0.15 | 1.82 | 1.26 | 1.13 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 348.76 | 5.52 | 2.99 | 22.69 | 18.05 | 14.61 |
| Tomida et al. | 341.95 | 5.00 | 2.89 | 21.66 | 18.28 | 14.87 |
| Kim et al. | 41.40 | 2.31 | 1.26 | 11.80 | 8.92 | 7.50 |
| Lin | 0.05 | 4.11 | 1.96 | 21.39 | 17.46 | 13.61 |
| Kim, Kim and Seo | 0.09 | 6.19 | 2.53 | 22.48 | 19.35 | 13.79 |
| Ojaswi et al. | 0.04 | 2.22 | 1.04 | 11.28 | 9.45 | 7.08 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.37 | 0.33 | 3.38 | 4.73 | 0.85 | 4.21 |
| Dufour-Sans et al. | 0.32 | 0.03 | 3.51 | 4.43 | 0.08 | 4.50 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 3.88 | 4.82 | 38.55 | 42.97 | 8.81 | 38.04 |
| Dufour-Sans et al. | 3.09 | 0.36 | 31.28 | 41.64 | 0.08 | 43.95 |

## Testing

```bash
go test ./...
go test -coverpkg=./... -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

`test/` runs the same cases against every scheme, and CI requires 100% statement coverage.
