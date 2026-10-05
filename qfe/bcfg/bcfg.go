package bcfg

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N int
	W group.Zp
	A group.Vector
	B group.Vector
}

type PublicKey struct {
	N int
	A []group.G1
	B []group.G2
	W group.G2
}

type Key struct {
	F  group.Matrix
	S1 group.G1
	S2 group.G1
}

type Ciphertext struct {
	C    []group.G1
	CHat []group.G1
	D    []group.G2
	DHat []group.G2
	E    group.G2
	EHat group.G2
}

func Setup(n int) (PublicKey, MasterKey) {
	w := group.RandomZp()
	a, b := group.RandomVector(n), group.RandomVector(n)
	pk := PublicKey{N: n, A: group.G1MulVec(a), B: group.G2MulVec(b), W: group.G2Mul(w)}
	return pk, MasterKey{N: n, W: w, A: a, B: b}
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function [][]int64) (Key, error) {
	f, err := group.IntMatrix(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	gamma := group.RandomZp()
	s1 := group.G1Mul(group.Add(group.Inner(msk.A, f.MulVec(msk.B)), group.Mul(gamma, msk.W)))
	return Key{F: f, S1: s1, S2: group.G1Mul(gamma)}, nil
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
	r, s, t, z := group.RandomZp(), group.RandomZp(), group.RandomZp(), group.RandomZp()
	blind := group.Sub(group.Sub(group.Mul(r, s), z), t)
	return Ciphertext{
		C:    group.MaskedG1(pk.A, r, x),
		CHat: group.MaskedG1(pk.A, t, x.Scale(s)),
		D:    group.MaskedG2(pk.B, s, y),
		DHat: group.MaskedG2(pk.B, z, y.Scale(r)),
		E:    group.G2Mul(blind),
		EHat: group.ScaleG2(pk.W, blind),
	}, nil
}

func Decrypt(table *group.DlogTable, pk PublicKey, sk Key, ct Ciphertext) (int64, bool) {
	var e group.PairingProduct
	e.MulBilinear(ct.C, sk.F, ct.D)
	e.DivBilinear(pk.A, sk.F, ct.DHat)
	e.DivBilinear(ct.CHat, sk.F, pk.B)
	e.Div([]group.G1{sk.S1}, []group.G2{ct.E})
	e.Mul([]group.G1{sk.S2}, []group.G2{ct.EHat})
	return table.Find(e.Value())
}
