# GoPFE for agents

Go functional encryption on BLS12-381 over gnark-crypto: six inner-product (IPFE) and two quadratic (QFE) schemes, the
Go counterpart of LibPFE and RustPFE. `README.md` is the user-facing overview.

## Commands

```bash
gofmt -l . && go vet ./...
go test -race -count=1 -coverpkg=./... -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1
GOARCH=386 go test -count=1 ./...
go test -run '^$' -bench . -benchtime 1x ./test
```

CI runs these, with formatting checked as `test -z "$(gofmt -l .)"`, and requires 100% statement coverage.

## Invariants

- API errors are returned: `Setup` wraps `group.ErrShape` for n < 1, `KeyGen` and `Encrypt` for wrong lengths, and
  `UnmarshalBinary` the sentinels in `group/encoding.go`. Panics are for internal invariants and for `Decrypt` on a key
  and ciphertext of different n.
- Scheme struct fields are unexported, so values come only from `Setup`, `KeyGen`, `Encrypt`, `Prepare` or
  `UnmarshalBinary`.
- Encodings are a 4-byte big-endian n, then the fields in declaration order with every length derived from n. Decoding
  validates every scalar and point and never allocates from a length read off the wire.
- Results are identical for any `GOMAXPROCS`; check with `go test -count=1 -cpu 1 ./...`. Prepared lines are copied per task because gnark's
  `MillerLoopFixedQ` mutates them.
- Keys, prepared keys and `DlogTable` never change after construction, and each `Decrypt` owns its `PairingProduct`.
- LibPFE, GoPFE and RustPFE keep the same constructions, test cases and benchmark inputs.
- Coverage comes from tests that reach a branch, never from reshaping code. No comments in code.

## Layout

- `group/`: the gnark wrapper (elements, fixed-base tables, pairing products, linear algebra, dlog, encoding).
- `ipfe/<scheme>/`, `qfe/<scheme>/`: one package per scheme with the same function set.
- `test/`: cases over every scheme through the adapters in `schemes_test.go`, and the benchmarks.
