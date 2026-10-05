package opt

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N  int
	A  group.Matrix
	B  group.Matrix
	Bi group.Matrix
}

type Key struct {
	R   []group.G2
	Vec []group.G2
}

type Ciphertext struct {
	R   []group.G1
	Vec []group.G1
}

func Setup(n int) MasterKey {
	b, inverse, _ := group.RandomInvertible(4)
	return MasterKey{N: n, A: group.RandomMatrix(2, n), B: b, Bi: inverse.Transpose()}
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	s := group.RandomVector(2)
	masked := s.MulMat(msk.A).Plus(f)
	return Key{
		R:   group.G2MulVec(msk.B.MulVec(group.Concat(s, msk.A.MulVec(masked)))),
		Vec: group.G2MulVec(masked),
	}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	s := group.RandomVector(2)
	return Ciphertext{
		R:   group.G1MulVec(msk.Bi.MulVec(group.Concat(msk.A.MulVec(m), s))),
		Vec: group.G1MulVec(s.MulMat(msk.A).Plus(m)),
	}, nil
}

func Decrypt(table *group.DlogTable, sk Key, ct Ciphertext) (int64, bool) {
	return decrypt(table, group.Affine(sk.R), group.Affine(sk.Vec), ct)
}

func DecryptMany(table *group.DlogTable, sk Key, cts []Ciphertext) []group.Decryption {
	r, vec := group.Prepare(sk.R), group.Prepare(sk.Vec)
	return group.DecryptEach(cts, func(ct Ciphertext) (int64, bool) { return decrypt(table, r, vec, ct) })
}

func decrypt(table *group.DlogTable, r, vec group.G2Side, ct Ciphertext) (int64, bool) {
	var e group.PairingProduct
	e.Mul(ct.Vec, vec)
	e.Div(ct.R, r)
	return table.Find(e.Value())
}
