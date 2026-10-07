package group

import (
	"math/big"
	"slices"
	"sync"

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

type jacobian[J, A any] interface {
	*J
	FromAffine(a *A) *J
	AddAssign(q *J) *J
	AddMixed(a *A) *J
	DoubleAssign() *J
	ScalarMultiplication(q *J, s *big.Int) *J
}

type affine[A any] interface {
	*A
	Neg(a *A) *A
}

type fixedBase[J, A any, PJ jacobian[J, A], PA affine[A]] struct {
	table     []A
	normalize func([]J) []A
}

const (
	windowBits  = 8
	windowCount = fr.Bytes
	windowSize  = 1 << (windowBits - 1)
)

var g1Generator, g2Generator, gtGenerator = generators()

var (
	g1Base = lazyFixedBase(g1Generator, bls12381.BatchJacobianToAffineG1)
	g2Base = lazyFixedBase(g2Generator, batchJacobianToAffineG2)
)

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

func lazyFixedBase[J, A any, PJ jacobian[J, A], PA affine[A]](
	generator A, normalize func([]J) []A,
) func() *fixedBase[J, A, PJ, PA] {
	return sync.OnceValue(func() *fixedBase[J, A, PJ, PA] {
		points := make([]J, windowCount*windowSize)
		var base J
		PJ(&base).FromAffine(&generator)
		for w := range windowCount {
			row := points[w*windowSize : (w+1)*windowSize]
			row[0] = base
			for j := 1; j < windowSize; j++ {
				row[j] = row[j-1]
				PJ(&row[j]).AddAssign(&base)
			}
			base = row[windowSize-1]
			PJ(&base).DoubleAssign()
		}
		return &fixedBase[J, A, PJ, PA]{table: normalize(points), normalize: normalize}
	})
}

func signedDigits(z Zp) [windowCount]int {
	bytes := z.Bytes()
	var digits [windowCount]int
	carry := 0
	for w := range windowCount {
		d := int(bytes[windowCount-1-w]) + carry
		carry = 0
		if d > windowSize {
			d -= 1 << windowBits
			carry = 1
		}
		digits[w] = d
	}
	return digits
}

func (b *fixedBase[J, A, PJ, PA]) sum(z Zp) J {
	var acc J
	for w, d := range signedDigits(z) {
		switch {
		case d > 0:
			PJ(&acc).AddMixed(&b.table[w*windowSize+d-1])
		case d < 0:
			p := b.table[w*windowSize-d-1]
			PA(&p).Neg(&p)
			PJ(&acc).AddMixed(&p)
		}
	}
	return acc
}

func (b *fixedBase[J, A, PJ, PA]) mulVec(v Vector) []A {
	sums := make([]J, len(v))
	for i := range v {
		sums[i] = b.sum(v[i])
	}
	return b.normalize(sums)
}

func (b *fixedBase[J, A, PJ, PA]) masked(base []A, r Zp, m Vector) []A {
	mustMatch(len(base), len(m))
	k := r.BigInt(new(big.Int))
	sums := make([]J, len(base))
	for i := range sums {
		encoded := b.sum(m[i])
		PJ(&sums[i]).FromAffine(&base[i])
		PJ(&sums[i]).ScalarMultiplication(&sums[i], k)
		PJ(&sums[i]).AddAssign(&encoded)
	}
	return b.normalize(sums)
}

func batchJacobianToAffineG2(points []bls12381.G2Jac) []G2 {
	result := make([]G2, len(points))
	var accumulator bls12381.E2
	accumulator.SetOne()
	for i := range points {
		if !points[i].Z.IsZero() {
			result[i].X = accumulator
			accumulator.Mul(&accumulator, &points[i].Z)
		}
	}
	var inverse bls12381.E2
	inverse.Inverse(&accumulator)
	for i := len(points) - 1; i >= 0; i-- {
		if points[i].Z.IsZero() {
			continue
		}
		var a, b bls12381.E2
		a.Mul(&result[i].X, &inverse)
		inverse.Mul(&inverse, &points[i].Z)
		b.Square(&a)
		result[i].X.Mul(&points[i].X, &b)
		result[i].Y.Mul(&points[i].Y, &b).Mul(&result[i].Y, &a)
	}
	return result
}

func G1Mul(z Zp) G1 {
	return G1MulVec(Vector{z})[0]
}

func G2Mul(z Zp) G2 {
	return G2MulVec(Vector{z})[0]
}

func G1MulVec(v Vector) []G1 {
	return g1Base().mulVec(v)
}

func G2MulVec(v Vector) []G2 {
	return g2Base().mulVec(v)
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
	return g1Base().masked(base, r, m)
}

func MaskedG2(base []G2, r Zp, m Vector) []G2 {
	return g2Base().masked(base, r, m)
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
