package opt

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n  int
	a  group.Matrix
	b  group.Matrix
	bi group.Matrix
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
	b, inverse, _ := group.RandomInvertible(4)
	return MasterKey{n: n, a: group.RandomMatrix(2, n), b: b, bi: inverse.Transpose()}, nil
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	s := group.RandomVector(2)
	masked := s.MulMat(msk.a).Plus(f)
	return Key{
		n:   msk.n,
		r:   group.G2MulVec(msk.b.MulVec(group.Concat(s, msk.a.MulVec(masked)))),
		vec: group.G2MulVec(masked),
	}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	s := group.RandomVector(2)
	return Ciphertext{
		n:   msk.n,
		r:   group.G1MulVec(msk.bi.MulVec(group.Concat(msk.a.MulVec(m), s))),
		vec: group.G1MulVec(s.MulMat(msk.a).Plus(m)),
	}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{r: group.Prepare(sk.r), vec: group.Prepare(sk.vec)}
}

func Decrypt[K DecryptionKey](table *group.DlogTable, sk K, ct Ciphertext) (int64, bool) {
	r, vec := sk.sides()
	var e group.PairingProduct
	e.Mul(ct.vec, vec)
	e.Div(ct.r, r)
	return table.Find(e.Value())
}

func (sk Key) sides() (r, vec group.G2Side) {
	return group.Affine(sk.r), group.Affine(sk.vec)
}

func (sk PreparedKey) sides() (r, vec group.G2Side) {
	return sk.r, sk.vec
}

func (msk MasterKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(msk.n).Matrix(msk.a).Matrix(msk.b).Matrix(msk.bi).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n:  n,
			a:  dec.Matrix(2, n),
			b:  dec.Matrix(4, 4),
			bi: dec.Matrix(4, 4),
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
			r:   dec.G2s(4),
			vec: dec.G2s(n),
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
			r:   dec.G1s(4),
			vec: dec.G1s(n),
		}
	})
}
