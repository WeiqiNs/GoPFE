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
`Decrypt` costs about two thirds to four fifths of `Decrypt` with the key; prepare a key that will decrypt many
ciphertexts. A QFE decryption also pairs the ciphertext's own G2 points, which no key can prepare, so a prepared Baltico
et al. key saves about a tenth on one core and up to a few percent on all cores, and a prepared Dufour-Sans et al. key,
which fixes one G2 point, decrypts in about the time of the plain key. A prepared key holds about 24 KB per G2 point.

Keys, prepared keys, master and public keys and `group.DlogTable`s are never modified after they are built, so any
number of goroutines may decrypt different ciphertexts with them at once. Each `Decrypt` builds its own
`group.PairingProduct`, which belongs to the goroutine that built it. Operations also split their own work across up to
`GOMAXPROCS` goroutines. Multi-pairings, `Prepare`, generator multiples and masked multiples split into tasks of
`pointsPerTask` points and matrix inversion into tasks of `rowsPerTask` rows, so smaller inputs stay on the calling
goroutine; a quadratic-form decryption gives each column of its bilinear form a task of its own. Results do not depend
on the split, and `GOMAXPROCS` (or `go test -cpu`) bounds the cores used.

The `group` package wraps gnark-crypto's BLS12-381 with the operations the schemes need: `Zp`, `G1`, `G2` and `GT`,
vectors and matrices over Zp, multi-pairings and baby-step giant-step discrete logarithms. Multiples of the G1 and G2
generators come from fixed-base tables built on first use, and a vector of them is split across cores like the
operations above.

## Benchmarks

`test/bench_test.go` times every scheme with the same input sizes and bounds as LibPFE's benchmark and checks each
decryption against the true result before timing it. Run it with `go test -run '^$' -bench . ./test`.

The numbers below are milliseconds per operation on all 16 hardware threads of an AMD Ryzen 7 9800X3D, the default
`GOMAXPROCS`, measured with Go 1.27 and gnark-crypto v0.22; add `-cpu 1` (or set `GOMAXPROCS=1`) for single-core
numbers. Inputs are random vectors (and matrices) whose results lie in [0, 10000]. Fixed-base schemes reuse one
discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al. search the range on every decryption.
Prepare is the one-time cost of `Prepare(sk)`, and Prepared Dec decrypts with the prepared key. Prepared Dec/s on 16
threads is the throughput of `b.RunParallel`: `GOMAXPROCS` goroutines decrypting at once with one shared prepared key
(and table).

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec | Prepared Dec/s on 16 threads |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.27 | 0.32 | 0.17 | 2.31 | 1.36 | 1.78 | 3396 |
| Tomida et al. | 0.52 | 0.29 | 0.16 | 1.59 | 1.24 | 1.08 | 4674 |
| Kim et al. | 0.05 | 0.23 | 0.12 | 1.94 | 0.99 | 1.51 | 5492 |
| Lin | 0.01 | 0.25 | 0.14 | 1.40 | 1.06 | 0.97 | 5110 |
| Kim, Kim and Seo | 0.01 | 0.31 | 0.17 | 1.70 | 1.36 | 1.17 | 4291 |
| Ojaswi et al. | 0.01 | 0.29 | 0.15 | 1.68 | 1.26 | 1.09 | 7672 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec | Prepared Dec/s on 16 threads |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 21.15 | 0.95 | 0.55 | 4.07 | 2.66 | 2.81 | 644 |
| Tomida et al. | 21.99 | 0.91 | 0.53 | 3.25 | 2.46 | 2.08 | 682 |
| Kim et al. | 5.14 | 0.61 | 0.31 | 2.98 | 2.08 | 2.40 | 1220 |
| Lin | 0.05 | 0.68 | 0.30 | 3.23 | 2.44 | 2.05 | 686 |
| Kim, Kim and Seo | 0.09 | 0.69 | 0.31 | 3.25 | 2.55 | 2.07 | 672 |
| Ojaswi et al. | 0.04 | 0.61 | 0.29 | 2.16 | 2.32 | 1.77 | 1293 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec | Prepared Dec/s on 16 threads |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.34 | 0.33 | 3.15 | 2.62 | 0.90 | 2.45 | 1992 |
| Dufour-Sans et al. | 0.31 | 0.02 | 3.30 | 2.00 | 0.08 | 2.08 | 1846 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec | Prepared Dec/s on 16 threads |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.82 | 1.07 | 5.80 | 5.61 | 2.01 | 5.59 | 226 |
| Dufour-Sans et al. | 0.80 | 0.21 | 6.57 | 6.43 | 0.08 | 6.42 | 198 |

## Testing

```bash
go test ./...
go test -race -coverpkg=./... -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

`test/` runs the same cases against every scheme, and CI requires 100% statement coverage.
