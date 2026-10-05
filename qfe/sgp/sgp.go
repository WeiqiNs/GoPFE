package sgp

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N int
	S group.Vector
	T group.Vector
}

type PublicKey struct {
	N int
	S []group.G1
	T []group.G2
}

type Key struct {
	F      group.Matrix
	Secret group.G2
}

type Ciphertext struct {
	Gamma group.G1
	A0    []group.G1
	A1    []group.G1
	B0    []group.G2
	B1    []group.G2
}

func Setup(n int) (PublicKey, MasterKey) {
	s, t := group.RandomVector(n), group.RandomVector(n)
	return PublicKey{N: n, S: group.G1MulVec(s), T: group.G2MulVec(t)}, MasterKey{N: n, S: s, T: t}
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function [][]int64) (Key, error) {
	f, err := group.IntMatrix(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	return Key{F: f, Secret: group.G2Mul(group.Inner(msk.S, f.MulVec(msk.T)))}, nil
}

func Encrypt(pk PublicKey, left, right []int64) (Ciphertext, error) {
	x, err := group.IntVector(left, pk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	y, err := group.IntVector(right, pk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	gamma := group.RandomZp()
	w, inverse, _ := group.RandomInvertible(2)
	wi := inverse.Transpose()
	return Ciphertext{
		Gamma: group.G1Mul(gamma),
		A0:    group.MaskedG1(pk.S, group.Mul(gamma, wi.At(0, 1)), x.Scale(wi.At(0, 0))),
		A1:    group.MaskedG1(pk.S, group.Mul(gamma, wi.At(1, 1)), x.Scale(wi.At(1, 0))),
		B0:    group.MaskedG2(pk.T, group.Neg(w.At(0, 1)), y.Scale(w.At(0, 0))),
		B1:    group.MaskedG2(pk.T, group.Neg(w.At(1, 1)), y.Scale(w.At(1, 0))),
	}, nil
}

func Decrypt(table *group.DlogTable, sk Key, ct Ciphertext) (int64, bool) {
	var e group.PairingProduct
	e.Mul([]group.G1{ct.Gamma}, []group.G2{sk.Secret})
	e.MulBilinear(ct.A0, sk.F, ct.B0)
	e.MulBilinear(ct.A1, sk.F, ct.B1)
	return table.Find(e.Value())
}
