package tao

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N    int
	B    group.Matrix
	Bi   group.Matrix
	Base group.GT
}

type Key struct {
	Vec []group.G2
}

type Ciphertext struct {
	Vec []group.G1
}

type PreparedKey struct {
	Vec group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	side() group.G2Side
}

func Setup(n int) MasterKey {
	r := group.RandomZp()
	b, inverse, _ := group.RandomInvertible(2*n + 5)
	return MasterKey{N: n, B: b, Bi: inverse.Scale(r).Transpose(), Base: group.ExpGT(group.GTGenerator(), r)}
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	tail := group.Vector{group.RandomZp(), group.RandomZp(), {}}
	encoded := group.Concat(f, group.Zeros(msk.N+2), tail)
	return Key{Vec: group.G2MulVec(encoded.MulMat(msk.B))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	tail := group.Vector{group.RandomZp(), group.RandomZp(), {}, {}, {}}
	encoded := group.Concat(m, group.Zeros(msk.N), tail)
	return Ciphertext{Vec: group.G1MulVec(encoded.MulMat(msk.Bi))}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{Vec: group.Prepare(sk.Vec)}
}

func Decrypt[K DecryptionKey](table *group.DlogTable, sk K, ct Ciphertext) (int64, bool) {
	return table.Find(group.Pair(ct.Vec, sk.side()))
}

func (sk Key) side() group.G2Side {
	return group.Affine(sk.Vec)
}

func (sk PreparedKey) side() group.G2Side {
	return sk.Vec
}
