package bjk

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n  int
	b  group.Matrix
	bi group.Matrix
	d  group.Matrix
	di group.Matrix
}

type Key struct {
	n   int
	r   []group.G2
	vec []group.G2
}

type Ciphertext struct {
	n   int
	r   []group.G1
	vec []group.G1
}

type PreparedKey struct {
	r   group.Prepared
	vec group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	sides() (r, vec group.G2Side)
}

func Setup(n int) (MasterKey, error) {
	if err := group.CheckDimension(n); err != nil {
		return MasterKey{}, err
	}
	b, bInverse, _ := group.RandomInvertible(2*n + 4)
	d, dInverse, _ := group.RandomInvertible(2)
	return MasterKey{n: n, b: b, bi: bInverse.Transpose(), d: d, di: dInverse.Transpose()}, nil
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	beta, betaT := group.RandomZp(), group.RandomZp()
	encoded := group.Concat(f.Scale(beta), f.Scale(betaT), group.Vector{{}, beta, {}, betaT})
	return Key{
		n:   msk.n,
		r:   group.G2MulVec(group.Vector{beta, betaT}.MulMat(msk.d)),
		vec: group.G2MulVec(encoded.MulMat(msk.b)),
	}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	alpha, alphaT := group.RandomZp(), group.RandomZp()
	encoded := group.Concat(m.Scale(alpha), m.Scale(alphaT), group.Vector{alpha, {}, alphaT, {}})
	return Ciphertext{
		n:   msk.n,
		r:   group.G1MulVec(group.Vector{alpha, alphaT}.MulMat(msk.di)),
		vec: group.G1MulVec(encoded.MulMat(msk.bi)),
	}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{r: group.Prepare(sk.r), vec: group.Prepare(sk.vec)}
}

func Decrypt[K DecryptionKey](sk K, ct Ciphertext, lo, hi int64) (int64, bool) {
	r, vec := sk.sides()
	return group.Dlog(group.Pair(ct.r, r), group.Pair(ct.vec, vec), lo, hi)
}

func (sk Key) sides() (r, vec group.G2Side) {
	return group.Affine(sk.r), group.Affine(sk.vec)
}

func (sk PreparedKey) sides() (r, vec group.G2Side) {
	return sk.r, sk.vec
}

func (msk MasterKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(msk.n).Matrix(msk.b).Matrix(msk.bi).Matrix(msk.d).Matrix(msk.di).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n:  n,
			b:  dec.Matrix(2*n+4, 2*n+4),
			bi: dec.Matrix(2*n+4, 2*n+4),
			d:  dec.Matrix(2, 2),
			di: dec.Matrix(2, 2),
		}
	})
}

func (sk Key) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(sk.n).G2s(sk.r).G2s(sk.vec).Bytes(), nil
}

func (sk *Key) UnmarshalBinary(data []byte) error {
	return group.Decode(data, sk, func(dec *group.Decoder, n int) Key {
		return Key{
			n:   n,
			r:   dec.G2s(2),
			vec: dec.G2s(2*n + 4),
		}
	})
}

func (ct Ciphertext) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(ct.n).G1s(ct.r).G1s(ct.vec).Bytes(), nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	return group.Decode(data, ct, func(dec *group.Decoder, n int) Ciphertext {
		return Ciphertext{
			n:   n,
			r:   dec.G1s(2),
			vec: dec.G1s(2*n + 4),
		}
	})
}
