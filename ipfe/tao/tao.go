package tao

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n  int
	b  group.Matrix
	bi group.Matrix
	r  group.Zp
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
	r := group.RandomZp()
	b, inverse, _ := group.RandomInvertible(2*n + 5)
	return MasterKey{n: n, b: b, bi: inverse.Scale(r).Transpose(), r: r}, nil
}

func (msk MasterKey) Base() group.GT {
	return group.ExpGT(group.GTGenerator(), msk.r)
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	tail := group.Vector{group.RandomZp(), group.RandomZp(), {}}
	encoded := group.Concat(f, group.Zeros(msk.n+2), tail)
	return Key{n: msk.n, vec: group.G2MulVec(encoded.MulMat(msk.b))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	tail := group.Vector{group.RandomZp(), group.RandomZp(), {}, {}, {}}
	encoded := group.Concat(m, group.Zeros(msk.n), tail)
	return Ciphertext{n: msk.n, vec: group.G1MulVec(encoded.MulMat(msk.bi))}, nil
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
	return group.NewEncoder(msk.n).Matrix(msk.b).Matrix(msk.bi).Zp(msk.r).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n:  n,
			b:  dec.Matrix(2*n+5, 2*n+5),
			bi: dec.Matrix(2*n+5, 2*n+5),
			r:  dec.Zp(),
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
			vec: dec.G2s(2*n + 5),
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
			vec: dec.G1s(2*n + 5),
		}
	})
}
