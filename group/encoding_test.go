package group

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func offSubgroupG1(t *testing.T) G1 {
	t.Helper()
	var p G1
	p.Y.SetUint64(2)
	if !p.IsOnCurve() || p.IsInSubGroup() {
		t.Fatal("(0, 2) is not a G1 curve point outside the subgroup")
	}
	return p
}

func offSubgroupG2(t *testing.T) G2 {
	t.Helper()
	var twist bls12381.E2
	twist.A0.SetUint64(4)
	twist.A1.SetUint64(4)
	var p G2
	for k := uint64(1); ; k++ {
		p.X.A0.SetUint64(k)
		var rhs bls12381.E2
		rhs.Square(&p.X).Mul(&rhs, &p.X).Add(&rhs, &twist)
		if rhs.Legendre() == 1 {
			p.Y.Sqrt(&rhs)
			break
		}
	}
	if !p.IsOnCurve() || p.IsInSubGroup() {
		t.Fatal("the G2 fixture is not a curve point outside the subgroup")
	}
	return p
}

func TestEncodingRoundTripsEveryElementKind(t *testing.T) {
	withProcs(t, 4)
	type elements struct {
		n   int
		zp  Zp
		v   Vector
		m   Matrix
		g1  G1
		g1s []G1
		g2  G2
		g2s []G2
	}
	points := 2*pointsPerTask + 1
	want := elements{
		n: 3, zp: NewZp(-1), v: RandomVector(3), m: RandomMatrix(2, 3), g1s: G1MulVec(RandomVector(points)),
		g2: G2Mul(RandomZp()), g2s: G2MulVec(RandomVector(points)),
	}
	data := NewEncoder(want.n).Zp(want.zp).Vector(want.v).Matrix(want.m).G1(want.g1).G1s(want.g1s).G2(want.g2).
		G2s(want.g2s).Bytes()
	if size := 4 + 32 + 3*32 + 6*32 + 48 + points*48 + 96 + points*96; len(data) != size {
		t.Fatalf("encoded %d bytes, want %d", len(data), size)
	}
	var got elements
	err := Decode(data, &got, func(d *Decoder, n int) elements {
		return elements{n, d.Zp(), d.Vector(3), d.Matrix(2, 3), d.G1(), d.G1s(points), d.G2(), d.G2s(points)}
	})
	if err != nil {
		t.Fatalf("Decode() = %v, want nil", err)
	}
	if got.n != want.n {
		t.Errorf("n = %d, want %d", got.n, want.n)
	}
	if !got.zp.Equal(&want.zp) {
		t.Error("Zp differs after a round trip")
	}
	if !slices.Equal(got.v, want.v) {
		t.Error("Vector differs after a round trip")
	}
	for i := range 2 {
		for j := range 3 {
			if a, b := got.m.At(i, j), want.m.At(i, j); !a.Equal(&b) {
				t.Errorf("Matrix entry (%d, %d) differs after a round trip", i, j)
			}
		}
	}
	if !got.g1.Equal(&want.g1) {
		t.Error("the G1 identity differs after a round trip")
	}
	if !slices.Equal(got.g1s, want.g1s) {
		t.Error("G1s differ after a round trip")
	}
	if !got.g2.Equal(&want.g2) {
		t.Error("G2 differs after a round trip")
	}
	if !slices.Equal(got.g2s, want.g2s) {
		t.Error("G2s differ after a round trip")
	}
}

func TestDecodeRejectsMalformedInput(t *testing.T) {
	withProcs(t, 4)
	readEverything := func(d *Decoder, _ int) {
		d.Zp()
		d.Vector(2)
		d.Matrix(2, 2)
		d.G1()
		d.G1s(2)
		d.G2()
		d.G2s(2)
	}
	header := NewEncoder(1).Bytes()
	points := G2MulVec(RandomVector(2 * pointsPerTask))
	points = append(points, offSubgroupG2(t))
	generator, offSubgroup := G1Mul(NewZp(1)), offSubgroupG1(t)
	g1Uncompressed, g1OffSubgroup := generator.RawBytes(), offSubgroup.Bytes()
	cases := []struct {
		name  string
		input []byte
		read  func(d *Decoder, n int)
		want  error
	}{
		{"empty input", nil, readEverything, ErrTruncated},
		{"zero dimension", []byte{0, 0, 0, 0}, readEverything, ErrShape},
		{
			"dimension larger than the input", append([]byte{0x40, 0, 0, 0}, make([]byte, 64)...),
			func(d *Decoder, n int) { d.Matrix(n, n) },
			ErrTruncated,
		},
		{
			"matrix row wider than the input", slices.Concat(header, make([]byte, 64)),
			func(d *Decoder, _ int) { d.Matrix(2, 1<<27+1) },
			ErrTruncated,
		},
		{
			"scalar above the modulus", slices.Concat(header, bytes.Repeat([]byte{0xff}, 32)),
			readEverything,
			ErrInvalidScalar,
		},
		{
			"G1 point outside the subgroup", slices.Concat(header, g1OffSubgroup[:]),
			func(d *Decoder, _ int) { d.G1() },
			ErrInvalidPoint,
		},
		{
			"uncompressed G1 point", slices.Concat(header, g1Uncompressed[:48]),
			func(d *Decoder, _ int) { d.G1() },
			ErrInvalidPoint,
		},
		{
			"G2 point outside the subgroup in the last task", NewEncoder(1).G2s(points).Bytes(),
			func(d *Decoder, _ int) { d.G2s(len(points)) },
			ErrInvalidPoint,
		},
		{
			"trailing byte", append(NewEncoder(1).Zp(NewZp(7)).Bytes(), 0),
			func(d *Decoder, _ int) { d.Zp() },
			ErrTrailingBytes,
		},
	}
	for _, c := range cases {
		target := 42
		err := Decode(c.input, &target, func(d *Decoder, n int) int {
			c.read(d, n)
			return 0
		})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if target != 42 {
			t.Errorf("%s: the target changed to %d", c.name, target)
		}
	}
}
