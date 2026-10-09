package lin

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n  int
	s1 group.Vector
	s2 group.Vector
}

type Key struct {
	n   int
	vec []group.G2
}

type Ciphertext struct {
	n   int
	vec []group.G1
}

type PreparedKey struct {
	vec group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	side() group.G2Side
}

func Setup(n int) (MasterKey, error) {
	if err := group.CheckDimension(n); err != nil {
		return MasterKey{}, err
	}
	return MasterKey{n: n, s1: group.RandomVector(2 * n), s2: group.RandomVector(2*n + 1)}, nil
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	padded := group.Concat(f, group.Zeros(msk.n))
	key := group.Concat(group.Vector{group.Inner(padded, msk.s1)}, padded)
	r := group.RandomZp()
	return Key{n: msk.n, vec: group.G2MulVec(group.Concat(group.Vector{group.Neg(r)}, msk.s2.Scale(r).Plus(key)))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	r := group.RandomZp()
	ct := group.Concat(group.Vector{group.Neg(r)}, msk.s1.Scale(r).Plus(group.Concat(m, group.Zeros(msk.n))))
	return Ciphertext{n: msk.n, vec: group.G1MulVec(group.Concat(group.Vector{group.Inner(msk.s2, ct)}, ct))}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{vec: group.Prepare(sk.vec)}
}

func Decrypt[K DecryptionKey](table *group.DlogTable, sk K, ct Ciphertext) (int64, bool) {
	return table.Find(group.Pair(ct.vec, sk.side()))
}

func (sk Key) side() group.G2Side {
	return group.Affine(sk.vec)
}

func (sk PreparedKey) side() group.G2Side {
	return sk.vec
}

func (msk MasterKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(msk.n).Vector(msk.s1).Vector(msk.s2).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n:  n,
			s1: dec.Vector(2 * n),
			s2: dec.Vector(2*n + 1),
		}
	})
}

func (sk Key) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(sk.n).G2s(sk.vec).Bytes(), nil
}

func (sk *Key) UnmarshalBinary(data []byte) error {
	return group.Decode(data, sk, func(dec *group.Decoder, n int) Key {
		return Key{
			n:   n,
			vec: dec.G2s(2*n + 2),
		}
	})
}

func (ct Ciphertext) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(ct.n).G1s(ct.vec).Bytes(), nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	return group.Decode(data, ct, func(dec *group.Decoder, n int) Ciphertext {
		return Ciphertext{
			n:   n,
			vec: dec.G1s(2*n + 2),
		}
	})
}
