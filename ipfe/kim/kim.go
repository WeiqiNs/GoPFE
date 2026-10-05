package kim

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N   int
	Det group.Zp
	B   group.Matrix
	Bi  group.Matrix
}

type Key struct {
	R   group.G2
	Vec []group.G2
}

type Ciphertext struct {
	R   group.G1
	Vec []group.G1
}

func Setup(n int) MasterKey {
	b, inverse, det := group.RandomInvertible(n)
	return MasterKey{N: n, Det: det, B: b, Bi: inverse.Scale(det).Transpose()}
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	alpha := group.RandomZp()
	return Key{R: group.G2Mul(group.Mul(alpha, msk.Det)), Vec: group.G2MulVec(f.Scale(alpha).MulMat(msk.B))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	beta := group.RandomZp()
	return Ciphertext{R: group.G1Mul(beta), Vec: group.G1MulVec(m.Scale(beta).MulMat(msk.Bi))}, nil
}

func Decrypt(sk Key, ct Ciphertext, lo, hi int64) (int64, bool) {
	return group.Dlog(group.PairOne(ct.R, sk.R), group.Pair(ct.Vec, sk.Vec), lo, hi)
}
