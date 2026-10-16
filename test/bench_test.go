package test

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
)

const bound = 10000

func randomEntries(rng *rand.Rand, n int, largest int64) []int64 {
	v := make([]int64, n)
	for i := range v {
		v[i] = rng.Int64N(largest + 1)
	}
	return v
}

func innerProductSample(n int) (x, y []int64, value int64) {
	rng := rand.New(rand.NewPCG(uint64(n), 2))
	largest := int64(math.Sqrt(bound / float64(n)))
	x, y = randomEntries(rng, n, largest), randomEntries(rng, n, largest)
	for i := range n {
		value += x[i] * y[i]
	}
	return x, y, value
}

func quadraticSample(n int) (x, y []int64, f [][]int64, value int64) {
	rng := rand.New(rand.NewPCG(uint64(n), 3))
	largest := int64(math.Cbrt(bound / float64(n*n)))
	x, y = randomEntries(rng, n, largest), randomEntries(rng, n, largest)
	f = make([][]int64, n)
	for i := range f {
		f[i] = randomEntries(rng, n, largest)
		for j := range n {
			value += x[i] * f[i][j] * y[j]
		}
	}
	return x, y, f, value
}

func benchmarkSchemes(b *testing.B, schemes []scheme) {
	for _, n := range []int{10, 100} {
		for _, s := range schemes {
			b.Run(fmt.Sprintf("n=%d/%s", n, s.schemeName()), func(b *testing.B) { s.benchmark(b, n) })
		}
	}
}

func BenchmarkInnerProduct(b *testing.B) { benchmarkSchemes(b, innerProductSchemes) }

func BenchmarkQuadratic(b *testing.B) { benchmarkSchemes(b, quadraticSchemes) }

type benchmarkInputs[K, P, C any] struct {
	setup, keyGen, encrypt func()
	sk                     K
	ct                     C
	want                   int64
	prepare                func(K) P
	decrypt                decryptor[K, C]
	decryptPrepared        decryptor[P, C]
}

func (in benchmarkInputs[K, P, C]) run(b *testing.B) {
	prepared := in.prepare(in.sk)
	if got, ok := in.decrypt(in.sk, in.ct); got != in.want || !ok {
		b.Fatalf("decrypted (%d, %v), want (%d, true)", got, ok, in.want)
	}
	if got, ok := in.decryptPrepared(prepared, in.ct); got != in.want || !ok {
		b.Fatalf("the prepared key decrypted (%d, %v), want (%d, true)", got, ok, in.want)
	}
	b.Run("Setup", func(b *testing.B) {
		for b.Loop() {
			in.setup()
		}
	})
	b.Run("KeyGen", func(b *testing.B) {
		for b.Loop() {
			in.keyGen()
		}
	})
	b.Run("Enc", func(b *testing.B) {
		for b.Loop() {
			in.encrypt()
		}
	})
	b.Run("Dec", func(b *testing.B) {
		for b.Loop() {
			in.decrypt(in.sk, in.ct)
		}
	})
	b.Run("Prepare", func(b *testing.B) {
		for b.Loop() {
			in.prepare(in.sk)
		}
	})
	b.Run("PreparedDec", func(b *testing.B) {
		for b.Loop() {
			in.decryptPrepared(prepared, in.ct)
		}
	})
	b.Run("PreparedDecParallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				in.decryptPrepared(prepared, in.ct)
			}
		})
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "dec/s")
	})
}

func (s innerProduct[M, K, P, C]) benchmark(b *testing.B, n int) {
	x, y, want := innerProductSample(n)
	msk := must(s.setup(n))
	decrypt, decryptPrepared := s.decryptors(msk, 0, bound)
	benchmarkInputs[K, P, C]{
		setup:           func() { s.setup(n) },
		keyGen:          func() { must(s.keyGen(msk, y)) },
		encrypt:         func() { must(s.encrypt(msk, x)) },
		sk:              must(s.keyGen(msk, y)),
		ct:              must(s.encrypt(msk, x)),
		want:            want,
		prepare:         s.prepare,
		decrypt:         decrypt,
		decryptPrepared: decryptPrepared,
	}.run(b)
}

func (s quadratic[PK, M, K, P, C]) benchmark(b *testing.B, n int) {
	x, y, f, want := quadraticSample(n)
	pk, msk := s.mustSetup(n)
	decrypt, decryptPrepared := s.decryptors(pk, 0, bound)
	benchmarkInputs[K, P, C]{
		setup:           func() { s.setup(n) },
		keyGen:          func() { must(s.keyGen(msk, f)) },
		encrypt:         func() { must(s.encrypt(pk, x, y)) },
		sk:              must(s.keyGen(msk, f)),
		ct:              must(s.encrypt(pk, x, y)),
		want:            want,
		prepare:         s.prepare,
		decrypt:         decrypt,
		decryptPrepared: decryptPrepared,
	}.run(b)
}
