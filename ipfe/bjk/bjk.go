package bjk

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N  int
	B  group.Matrix
	Bi group.Matrix
	D  group.Matrix
	Di group.Matrix
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
	b, bInverse, _ := group.RandomInvertible(2*n + 4)
	d, dInverse, _ := group.RandomInvertible(2)
	return MasterKey{N: n, B: b, Bi: bInverse.Transpose(), D: d, Di: dInverse.Transpose()}
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	beta, betaT := group.RandomZp(), group.RandomZp()
	encoded := group.Concat(f.Scale(beta), f.Scale(betaT), group.Vector{{}, beta, {}, betaT})
	return Key{
		R:   group.G2MulVec(group.Vector{beta, betaT}.MulMat(msk.D)),
		Vec: group.G2MulVec(encoded.MulMat(msk.B)),
	}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	alpha, alphaT := group.RandomZp(), group.RandomZp()
	encoded := group.Concat(m.Scale(alpha), m.Scale(alphaT), group.Vector{alpha, {}, alphaT, {}})
	return Ciphertext{
		R:   group.G1MulVec(group.Vector{alpha, alphaT}.MulMat(msk.Di)),
		Vec: group.G1MulVec(encoded.MulMat(msk.Bi)),
	}, nil
}

func Decrypt(sk Key, ct Ciphertext, lo, hi int64) (int64, bool) {
	return group.Dlog(group.Pair(ct.R, sk.R), group.Pair(ct.Vec, sk.Vec), lo, hi)
}
