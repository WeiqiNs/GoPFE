package lin

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N  int
	S1 group.Vector
	S2 group.Vector
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
	return MasterKey{N: n, S1: group.RandomVector(2 * n), S2: group.RandomVector(2*n + 1)}
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	padded := group.Concat(f, group.Zeros(msk.N))
	key := group.Concat(group.Vector{group.Inner(padded, msk.S1)}, padded)
	r := group.RandomZp()
	return Key{Vec: group.G2MulVec(group.Concat(group.Vector{group.Neg(r)}, msk.S2.Scale(r).Plus(key)))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	r := group.RandomZp()
	ct := group.Concat(group.Vector{group.Neg(r)}, msk.S1.Scale(r).Plus(group.Concat(m, group.Zeros(msk.N))))
	return Ciphertext{Vec: group.G1MulVec(group.Concat(group.Vector{group.Inner(msk.S2, ct)}, ct))}, nil
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
