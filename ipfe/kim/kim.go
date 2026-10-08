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

type PreparedKey struct {
	R   group.Prepared
	Vec group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	sides() (r, vec group.G2Side)
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

func Prepare(sk Key) PreparedKey {
	return PreparedKey{R: group.Prepare([]group.G2{sk.R}), Vec: group.Prepare(sk.Vec)}
}

func Decrypt[K DecryptionKey](sk K, ct Ciphertext, lo, hi int64) (int64, bool) {
	r, vec := sk.sides()
	return group.Dlog(group.Pair([]group.G1{ct.R}, r), group.Pair(ct.Vec, vec), lo, hi)
}

func (sk Key) sides() (r, vec group.G2Side) {
	return group.Affine{sk.R}, group.Affine(sk.Vec)
}

func (sk PreparedKey) sides() (r, vec group.G2Side) {
	return sk.R, sk.Vec
}
