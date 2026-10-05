package group

import "testing"

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", name)
		}
	}()
	f()
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

func TestInvertRejectsSingularMatrices(t *testing.T) {
	if _, _, ok := intMatrix(t, [][]int64{{1, 2}, {2, 4}}).invert(); ok {
		t.Error("a singular matrix was inverted")
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
	two, three := RandomVector(2), RandomVector(3)
	m := RandomMatrix(2, 3)
	mustPanic(t, "NewDlogTable(lo > hi)", func() { NewDlogTable(GTGenerator(), 1, 0) })
	mustPanic(t, "Plus", func() { two.Plus(three) })
	mustPanic(t, "Inner", func() { Inner(two, three) })
	mustPanic(t, "MulVec", func() { m.MulVec(two) })
	mustPanic(t, "MulMat", func() { three.MulMat(m) })
	mustPanic(t, "MSMG1", func() { MSMG1(G1MulVec(two), three) })
	mustPanic(t, "MaskedG1", func() { MaskedG1(G1MulVec(two), NewZp(1), three) })
	mustPanic(t, "MaskedG2", func() { MaskedG2(G2MulVec(two), NewZp(1), three) })
	mustPanic(t, "Pair", func() { Pair(G1MulVec(two), G2MulVec(three)) })
	mustPanic(t, "PairingProduct.Mul", func() {
		var e PairingProduct
		e.Mul(G1MulVec(two), G2MulVec(three))
	})
}
