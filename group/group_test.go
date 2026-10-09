package group

import (
	"errors"
	"math/big"
	"runtime"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", name)
		}
	}()
	f()
}

func withProcs(t *testing.T, procs int) {
	previous := runtime.GOMAXPROCS(procs)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
}

func intMatrix(t *testing.T, rows [][]int64) Matrix {
	t.Helper()
	m, err := IntMatrix(rows, len(rows))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInvertSwapsZeroPivotsAndTracksTheDeterminant(t *testing.T) {
	m := intMatrix(t, [][]int64{{0, 2}, {3, 0}})
	inverse, det, ok := m.invert()
	want := NewZp(-6)
	if !ok || !det.Equal(&want) {
		t.Fatalf("got det %v ok %v, want -6", det.String(), ok)
	}
	v := Vector{NewZp(5), NewZp(7)}
	if got := inverse.MulVec(m.MulVec(v)); !got[0].Equal(&v[0]) || !got[1].Equal(&v[1]) {
		t.Errorf("inverse(m) * m * v = %v, want %v", got, v)
	}
}

func TestInvertSplitAcrossTasks(t *testing.T) {
	withProcs(t, 4)
	m, inverse, _ := RandomInvertible(2*rowsPerTask + 1)
	v := RandomVector(m.rows)
	if got := inverse.MulVec(m.MulVec(v)); !slices.Equal(got, v) {
		t.Error("inverse(m) * m * v differs from v")
	}
}

func TestInvertRejectsSingularMatrices(t *testing.T) {
	if _, _, ok := intMatrix(t, [][]int64{{1, 2}, {2, 4}}).invert(); ok {
		t.Error("a singular matrix was inverted")
	}
}

func TestGeneratorTablesMatchScalarMultiplicationBase(t *testing.T) {
	withProcs(t, 4)
	scalars := Concat(Vector{NewZp(0), NewZp(-1)}, RandomVector(4*pointsPerTask))
	r, m := RandomZp(), RandomVector(len(scalars))
	g1s, g2s := G1MulVec(scalars), G2MulVec(scalars)
	masked1, masked2 := MaskedG1(g1s, r, m), MaskedG2(g2s, r, m)
	for i, z := range scalars {
		maskedScalar := Add(Mul(z, r), m[i])
		k, kMasked := z.BigInt(new(big.Int)), maskedScalar.BigInt(new(big.Int))
		var want1, wantMasked1 G1
		var want2, wantMasked2 G2
		want1.ScalarMultiplicationBase(k)
		want2.ScalarMultiplicationBase(k)
		wantMasked1.ScalarMultiplicationBase(kMasked)
		wantMasked2.ScalarMultiplicationBase(kMasked)
		if !g1s[i].Equal(&want1) || !g2s[i].Equal(&want2) {
			t.Errorf("generator multiples of %s differ from ScalarMultiplicationBase", z.String())
		}
		if !masked1[i].Equal(&wantMasked1) || !masked2[i].Equal(&wantMasked2) {
			t.Errorf("masked multiples of %s differ from ScalarMultiplicationBase", z.String())
		}
	}
}

func TestPairingProductSplitAcrossTasksMatchesGnarkPair(t *testing.T) {
	withProcs(t, 4)
	size := 4*pointsPerTask + 1
	ps, qs := G1MulVec(RandomVector(size)), G2MulVec(RandomVector(size))
	want := must(bls12381.Pair(ps, qs))
	for _, plain := range []int{0, size / 2} {
		var e PairingProduct
		e.Mul(ps[:plain], Affine(qs[:plain]))
		e.Mul(ps[plain:], Prepare(qs[plain:]))
		for call := range 2 {
			if got := e.Value(); !got.Equal(&want) {
				t.Errorf("Value call %d with %d plain pairs differs from bls12381.Pair", call+1, plain)
			}
		}
	}
}

func TestDlogTableFindsExactlyTheRange(t *testing.T) {
	base := GTGenerator()
	table := NewDlogTable(base, -5, 10)
	cases := []struct {
		exponent int64
		ok       bool
	}{{-5, true}, {0, true}, {7, true}, {10, true}, {11, false}, {-6, false}}
	for _, c := range cases {
		if got, ok := table.Find(ExpGT(base, NewZp(c.exponent))); ok != c.ok || (ok && got != c.exponent) {
			t.Errorf("Find(base^%d) = (%d, %v), want ok %v", c.exponent, got, ok, c.ok)
		}
	}
}

func TestDlogTableOnTheIdentity(t *testing.T) {
	var one GT
	one.SetOne()
	table := NewDlogTable(one, 3, 9)
	if got, ok := table.Find(one); got != 3 || !ok {
		t.Errorf("Find(1) = (%d, %v), want (3, true)", got, ok)
	}
	if _, ok := table.Find(GTGenerator()); ok {
		t.Error("found a non-identity element in a table over the identity")
	}
}

func TestMismatchedLengthsPanic(t *testing.T) {
	withProcs(t, 4)
	two, three := RandomVector(2), RandomVector(3)
	m := RandomMatrix(2, 3)
	mustPanic(t, "NewDlogTable(lo > hi)", func() { NewDlogTable(GTGenerator(), 1, 0) })
	mustPanic(t, "Plus", func() { two.Plus(three) })
	mustPanic(t, "Inner", func() { Inner(two, three) })
	mustPanic(t, "MulVec", func() { m.MulVec(two) })
	mustPanic(t, "MulMat", func() { three.MulMat(m) })
	mustPanic(t, "must", func() { must(0, errors.New("group: failed")) })
	mustPanic(t, "MulBilinear", func() { new(PairingProduct).MulBilinear(G1MulVec(three), m, G2MulVec(three)) })
	mustPanic(t, "MaskedG1", func() { MaskedG1(G1MulVec(two), NewZp(1), three) })
	mustPanic(t, "MaskedG2", func() { MaskedG2(G2MulVec(two), NewZp(1), three) })
	mustPanic(t, "Pair", func() { Pair(G1MulVec(two), Affine(G2MulVec(three))) })
	mustPanic(t, "Pair(Prepared)", func() { Pair(G1MulVec(two), Prepare(G2MulVec(three))) })
}
