# GoPFE for agents

Pairing-based functional encryption in Go on BLS12-381 over gnark-crypto: six inner-product (`ipfe/`) and two
quadratic (`qfe/`) schemes. It is one of four implementations of the same eight schemes: LibPFE (C++), RustPFE
(Rust/Python) and CudaPFE (CPU/GPU batching). LibPFE, GoPFE and RustPFE share the test cases in `test/ipfe_test.go`
and `test/qfe_test.go` and the benchmark inputs in `test/bench_test.go`. `README.md` is the user-facing overview.

## Commands

CI runs these, with the Go version from `go.mod`:

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test -race -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
GOARCH=386 go test -count=1 ./...
go tool cover -func=coverage.out | awk '/^total:/ { print; if ($3 != "100.0%") exit 1 }'
go test -run '^$' -bench . -benchtime 1x ./test
```

`-coverpkg=./...` matters: scheme packages have no tests of their own and are covered only through `test/`.
`go test -count=1 -cpu 1 ./...` checks single-core runs, which CI does not do.

## Layout

- `group/group.go`: type aliases `Zp`, `G1`, `G2`, `GT`; fixed-base generator tables (`G1MulVec`, `G2MulVec`,
  `MaskedG1`, `MaskedG2`); `Prepare`, `Pair`, `PairingProduct`; `parallelize`, which splits work across `GOMAXPROCS`.
- `group/linalg.go`: `Vector`, `Matrix`, `IntVector`/`IntMatrix` (int64 input to `Zp`, `ErrShape` on bad shape),
  `RandomInvertible` (parallel Gauss-Jordan with determinant), `CheckDimension`.
- `group/dlog.go`: `DlogTable` (baby-step giant-step over [lo, hi]) and the one-shot `Dlog`.
- `group/encoding.go`: `Encoder`, `Decoder`, `Decode` and the decoding sentinels `ErrTruncated`, `ErrTrailingBytes`,
  `ErrInvalidScalar`, `ErrInvalidPoint`.
- `ipfe/{bjk,tao,kim,lin,kks,opt}`, `qfe/{bcfg,sgp}`: one package per scheme, one file each.
- `test/schemes_test.go`: the scheme registries `innerProductSchemes` and `quadraticSchemes` and generic adapters;
  `ipfe_test.go`/`qfe_test.go` run the same cases over every registered scheme; `bench_test.go` benchmarks them.

## Scheme shape and data flow

Each scheme package exports `MasterKey`, `Key`, `Ciphertext`, `PreparedKey` (QFE adds `PublicKey`) and `Setup`,
`KeyGen`, `Encrypt`, `Prepare`, `Decrypt`. `Decrypt` is generic over the package's `DecryptionKey` constraint
(`Key | PreparedKey`), whose unexported accessor (`sides`, `side` or `split`) yields a `group.G2Side`: `group.Affine`
for a plain key, `group.Prepared` for precomputed Miller-loop lines. `PairingProduct.Mul` routes the first to
`MillerLoop` and the second to `MillerLoopFixedQ`, then `Value` applies one final exponentiation.

Decryption ends in a discrete log. `bjk` and `kim` take `lo, hi` and call `group.Dlog`, because their base is a
pairing computed per ciphertext. The rest take a shared `*group.DlogTable` built over `Base()`, except `tao`, whose
base depends on the master key: `MasterKey.Base`. The test adapters mirror this split: `rangeDecryptors` versus
`tableDecryptors`.

To add a scheme: create `ipfe/<name>` or `qfe/<name>` with the function set above plus `MarshalBinary` and
`UnmarshalBinary` on every key and ciphertext type, built from `group.NewEncoder` and `group.Decode`, with the reader
listing fields in the encoder's order. Register it in `innerProductSchemes` or `quadraticSchemes`, which puts it under
`TestInnerProduct`/`TestQuadratic` and the benchmarks and is what makes the coverage gate reach it. Add it to the
scheme tables in `README.md`. The same construction belongs in LibPFE, RustPFE and CudaPFE.

## Design facts

- Input errors are returned, not panicked: `Setup` gets `ErrShape` from `group.CheckDimension`, and `KeyGen`/`Encrypt`
  get it from `IntVector`/`IntMatrix` (cases `RejectsDimensionsBelowOne`, `RejectsVectorsOfTheWrongLength`,
  `RejectsInputsOfTheWrongShape`). Mismatched internal lengths, including `Decrypt` on a key and ciphertext of
  different n, panic in `group.mustMatch`; `NewDlogTable` panics on lo > hi (`TestMismatchedLengthsPanic`).
- Scheme struct fields are unexported, so values come only from the constructors or `UnmarshalBinary`. Every
  type with an encoding stores n, because n heads it.
- An encoding is n as 4 big-endian bytes, then the fields in the order the encoder writes them, every length derived
  from n. `Decode` rejects an n larger than the remaining bytes divided by `fr.Bytes`, `Decoder.take` compares counts
  by dividing the remaining length rather than multiplying, and `Decoder.Matrix` checks `cols` before multiplying, so
  no length from the wire overflows a 32-bit `int` or sizes an allocation. Points decode compressed with gnark's
  subgroup check; `Decode` leaves its target untouched on error. Pinned by `TestDecodeRejectsMalformedInput`
  (its 2^27+1-column row size overflows only a 32-bit `int`, hence the `GOARCH=386` CI step) and `rejectsTruncated` per scheme.
- Results do not depend on `GOMAXPROCS`. Group tests force splits with `withProcs(t, 4)` and compare against gnark
  (`TestGeneratorTablesMatchScalarMultiplicationBase`, `TestPairingProductSplitAcrossTasksMatchesGnarkPair`,
  `TestInvertSplitAcrossTasks`). Task sizes are the constants `pointsPerTask` and `rowsPerTask` in `group`.
- `PairingProduct.Value` copies prepared lines per task because `MillerLoopFixedQ` overwrites its `lines` argument;
  `TestPairingProductSplitAcrossTasksMatchesGnarkPair` calls `Value` twice to catch that.
- Keys, prepared keys, `DlogTable` and the lazily built generator tables (`g1Base`, `g2Base`, `sync.OnceValue`) are
  read-only after construction, and each `Decrypt` owns its `PairingProduct`, so one key and table serve many
  goroutines (`ThreadsShareOneKeyAndTable`, under `-race` in CI).
- `DlogTable` does its arithmetic in `uint64`, and `babyStepCount` takes the integer square root by division, so the
  arithmetic cannot overflow for any int64 bounds; duplicate baby steps keep the smallest exponent (`TestDlogTableFindsExactlyTheRange`,
  `TestDlogTableOnTheIdentity`).

## CI

`.github/workflows/ci.yml`, on pushes and pull requests to main and on manual dispatch. Job `coverage`: gofmt, vet, race tests with a coverage
profile, the 32-bit test run, the 100% statement gate, then a Codecov upload over OIDC. Job `bench`: every benchmark
once, as a smoke test.
