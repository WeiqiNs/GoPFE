# Pairing-based Functional Encryption in Go (GoPFE)

[![GoPFE CI](https://github.com/WeiqiNs/GoPFE/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/GoPFE/actions/workflows/ci.yml)

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
| Baltico et al. | `qfe/bcfg` | adaptive, generic group model | 2n G1 + (2n + 2) G2 | 2 G1 | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_3) |
| Dufour-Sans et al. | `qfe/sgp` | generic group model | (2n + 1) G1 + 2n G2 | 1 G2 | [NeurIPS 2019](https://proceedings.neurips.cc/paper_files/paper/2019/hash/9d28de8ff9bb6a3fa41fddfdc28f3bc1-Abstract.html) |

Both decrypt against a fixed base, and keys also carry F. Dufour-Sans et al.'s scheme appears in the NeurIPS paper by
Ryffel, Dufour-Sans, Gay, Bach and Pointcheval.

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
ciphertext, so their `Decrypt` takes the bounds instead. Baltico et al.'s `Decrypt` also takes the public key.

The `group` package wraps gnark-crypto's BLS12-381 with the operations the schemes need: `Zp`, `G1`, `G2` and `GT`,
vectors and matrices over Zp, multi-scalar multiplication, multi-pairings and baby-step giant-step discrete logarithms.

## Benchmarks

`test/bench_test.go` times every scheme with the same input sizes and bounds as LibPFE's benchmark and checks each
decryption against the true result before timing it. Run it with `go test -run '^$' -bench . ./test`.

The numbers below are milliseconds per operation, measured with Go 1.27 and gnark-crypto v0.22 on an AMD Ryzen 7
9800X3D. Inputs are random vectors (and matrices) whose results lie in [0, 10000]. Fixed-base schemes reuse one
discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al. search the range on every decryption.

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.63 | 0.85 | 0.50 | 3.69 |
| Tomida et al. | 1.09 | 0.67 | 0.39 | 2.78 |
| Kim et al. | 0.07 | 0.43 | 0.25 | 2.19 |
| Lin | 0.01 | 0.62 | 0.34 | 2.60 |
| Kim, Kim and Seo | 0.01 | 0.74 | 0.42 | 3.19 |
| Ojaswi et al. | 0.01 | 0.61 | 0.35 | 1.76 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Bishop et al. | 310.20 | 5.93 | 3.39 | 22.59 |
| Tomida et al. | 335.49 | 5.46 | 3.14 | 21.69 |
| Kim et al. | 39.80 | 2.61 | 1.38 | 11.68 |
| Lin | 0.05 | 4.56 | 2.19 | 21.61 |
| Kim, Kim and Seo | 0.09 | 4.69 | 2.25 | 22.39 |
| Ojaswi et al. | 0.04 | 2.53 | 1.23 | 11.27 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.64 | 0.11 | 4.32 | 6.14 |
| Dufour-Sans et al. | 0.53 | 0.10 | 4.16 | 4.10 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Baltico et al. | 3.65 | 0.48 | 36.34 | 59.99 |
| Dufour-Sans et al. | 3.38 | 0.46 | 35.68 | 39.73 |

## Testing

```bash
go test ./...
go test -coverpkg=./... -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

`test/` runs the same cases against every scheme, and CI requires 100% statement coverage.
