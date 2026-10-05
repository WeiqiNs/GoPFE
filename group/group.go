package group

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type (
	Zp = fr.Element
	G1 = bls12381.G1Affine
	G2 = bls12381.G2Affine
	GT = bls12381.GT
)

type Affine []G2

type Prepared [][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff

type G2Side interface {
	mulInto(e *PairingProduct, ps []G1)
}

var g1Generator, g2Generator, gtGenerator = generators()

func generators() (G1, G2, GT) {
	_, _, g1, g2 := bls12381.Generators()
	return g1, g2, PairOne(g1, g2)
}

func NewZp(v int64) Zp {
	var z Zp
	z.SetInt64(v)
	return z
}

func RandomZp() Zp {
	var z Zp
	z.MustSetRandom()
	return z
}

func Add(x, y Zp) Zp {
	var z Zp
	z.Add(&x, &y)
	return z
}

func Sub(x, y Zp) Zp {
	var z Zp
	z.Sub(&x, &y)
	return z
}

func Mul(x, y Zp) Zp {
	var z Zp
	z.Mul(&x, &y)
	return z
}

func Neg(x Zp) Zp {
	var z Zp
	z.Neg(&x)
	return z
}

func Inverse(x Zp) Zp {
	var z Zp
	z.Inverse(&x)
	return z
}

func G1Mul(z Zp) G1 {
	var p G1
	p.ScalarMultiplicationBase(z.BigInt(new(big.Int)))
	return p
}

func G2Mul(z Zp) G2 {
	var p G2
	p.ScalarMultiplicationBase(z.BigInt(new(big.Int)))
	return p
}

func G1MulVec(v Vector) []G1 {
	return bls12381.BatchScalarMultiplicationG1(&g1Generator, v)
}

func G2MulVec(v Vector) []G2 {
	return bls12381.BatchScalarMultiplicationG2(&g2Generator, v)
}

func ScaleG2(p G2, k Zp) G2 {
	var r G2
	r.ScalarMultiplication(&p, k.BigInt(new(big.Int)))
	return r
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func MSMG1(points []G1, scalars Vector) G1 {
	var r G1
	must(r.MultiExp(points, scalars, ecc.MultiExpConfig{}))
	return r
}

func MaskedG1(base []G1, r Zp, m Vector) []G1 {
	mustMatch(len(base), len(m))
	k := r.BigInt(new(big.Int))
	encoded := G1MulVec(m)
	sums := make([]bls12381.G1Jac, len(base))
	for i := range sums {
		sums[i].FromAffine(&base[i])
		sums[i].ScalarMultiplication(&sums[i], k)
		sums[i].AddMixed(&encoded[i])
	}
	return bls12381.BatchJacobianToAffineG1(sums)
}

func MaskedG2(base []G2, r Zp, m Vector) []G2 {
	mustMatch(len(base), len(m))
	k := r.BigInt(new(big.Int))
	points := G2MulVec(m)
	for i := range points {
		var sum bls12381.G2Jac
		sum.FromAffine(&base[i])
		sum.ScalarMultiplication(&sum, k)
		sum.AddMixed(&points[i])
		points[i].FromJacobian(&sum)
	}
	return points
}

func Prepare(qs []G2) Prepared {
	lines := make(Prepared, len(qs))
	for i := range qs {
		lines[i] = bls12381.PrecomputeLines(qs[i])
	}
	return lines
}

func Pair(ps []G1, qs G2Side) GT {
	var e PairingProduct
	e.Mul(ps, qs)
	return e.Value()
}

func PairOne(p G1, q G2) GT {
	return Pair([]G1{p}, Affine{q})
}

type PairingProduct struct {
	ps    []G1
	qs    []G2
	fixed []G1
	lines []Prepared
}

func (qs Affine) mulInto(e *PairingProduct, ps []G1) {
	mustMatch(len(ps), len(qs))
	e.ps = append(e.ps, ps...)
	e.qs = append(e.qs, qs...)
}

func (qs Prepared) mulInto(e *PairingProduct, ps []G1) {
	mustMatch(len(ps), len(qs))
	e.fixed = append(e.fixed, ps...)
	e.lines = append(e.lines, qs)
}

func (e *PairingProduct) Mul(ps []G1, qs G2Side) {
	qs.mulInto(e, ps)
}

func (e *PairingProduct) Div(ps []G1, qs G2Side) {
	negated := make([]G1, len(ps))
	for i := range ps {
		negated[i].Neg(&ps[i])
	}
	e.Mul(negated, qs)
}

func (e *PairingProduct) MulBilinear(p []G1, f Matrix, q []G2) {
	e.Mul(combine(p, f), Affine(q))
}

func (e *PairingProduct) Value() GT {
	var f GT
	f.SetOne()
	if len(e.ps) > 0 {
		loop := must(bls12381.MillerLoop(e.ps, e.qs))
		f.Mul(&f, &loop)
	}
	if len(e.fixed) > 0 {
		loop := must(bls12381.MillerLoopFixedQ(e.fixed, slices.Concat(e.lines...)))
		f.Mul(&f, &loop)
	}
	return bls12381.FinalExponentiation(&f)
}

func combine(p []G1, f Matrix) []G1 {
	combined := make([]G1, f.cols)
	for j := range combined {
		combined[j] = MSMG1(p, f.Column(j))
	}
	return combined
}

func GTGenerator() GT {
	return gtGenerator
}

func MulGT(x, y GT) GT {
	var z GT
	z.Mul(&x, &y)
	return z
}

func ExpGT(x GT, k Zp) GT {
	var z GT
	z.Exp(x, k.BigInt(new(big.Int)))
	return z
}
