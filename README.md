# Implementation of Inner Product Encryption in Go

[![GoIPE CI](https://github.com/WeiqiNs/GoIPE/actions/workflows/ci.yml/badge.svg)](https://github.com/WeiqiNs/GoIPE/actions/workflows/ci.yml)

Our application is built on the [PBC Go Wrapper](https://github.com/Nik-U/pbc). One need to install this library first
before running the implementation.

#### A sample run of our scheme, encrypting two random vectors of length 100, where each datapoint in the vector is less than 100.
```go
A, B, BStar, pp, phi, g, gt, e := Setup(100)
x := pp.VectorZpRandom(100)
y := pp.VectorZpRandom(100)

ctx1, ctc1, _, e := Encrypt(x, A, B, BStar, pp, g)
ctx2, _, ctk2, e := Encrypt(y, A, B, BStar, pp, g)

var table LookupTable
GenerateLookupTable(pp, gt, int32(1), int32(1000000), &table)

m, e := EvalWithTable(ctx1, ctc1, ctx2, ctk2, pp, phi, &table)
```
`m` will be the recovered inner-product.

## Acknowledgement
I thank [Dmytro Bogatov](https://dbogatov.org) for his valuable suggestions, insightful feedback, and hands-on code revisions throughout the development of this project.
