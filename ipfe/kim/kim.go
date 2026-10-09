package kim

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n   int
	det group.Zp
	b   group.Matrix
	bi  group.Matrix
}

type Key struct {
	n   int
	r   group.G2
	vec []group.G2
}

type Ciphertext struct {
	n   int
	r   group.G1
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
	b, inverse, det := group.RandomInvertible(n)
	return MasterKey{n: n, det: det, b: b, bi: inverse.Scale(det).Transpose()}, nil
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	alpha := group.RandomZp()
	return Key{n: msk.n, r: group.G2Mul(group.Mul(alpha, msk.det)), vec: group.G2MulVec(f.Scale(alpha).MulMat(msk.b))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	beta := group.RandomZp()
	return Ciphertext{n: msk.n, r: group.G1Mul(beta), vec: group.G1MulVec(m.Scale(beta).MulMat(msk.bi))}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{r: group.Prepare([]group.G2{sk.r}), vec: group.Prepare(sk.vec)}
}

func Decrypt[K DecryptionKey](sk K, ct Ciphertext, lo, hi int64) (int64, bool) {
	r, vec := sk.sides()
	return group.Dlog(group.Pair([]group.G1{ct.r}, r), group.Pair(ct.vec, vec), lo, hi)
}

func (sk Key) sides() (r, vec group.G2Side) {
	return group.Affine{sk.r}, group.Affine(sk.vec)
}

func (sk PreparedKey) sides() (r, vec group.G2Side) {
	return sk.r, sk.vec
}

func (msk MasterKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(msk.n).Zp(msk.det).Matrix(msk.b).Matrix(msk.bi).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n:   n,
			det: dec.Zp(),
			b:   dec.Matrix(n, n),
			bi:  dec.Matrix(n, n),
		}
	})
}

func (sk Key) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(sk.n).G2(sk.r).G2s(sk.vec).Bytes(), nil
}

func (sk *Key) UnmarshalBinary(data []byte) error {
	return group.Decode(data, sk, func(dec *group.Decoder, n int) Key {
		return Key{
			n:   n,
			r:   dec.G2(),
			vec: dec.G2s(n),
		}
	})
}

func (ct Ciphertext) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(ct.n).G1(ct.r).G1s(ct.vec).Bytes(), nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	return group.Decode(data, ct, func(dec *group.Decoder, n int) Ciphertext {
		return Ciphertext{
			n:   n,
			r:   dec.G1(),
			vec: dec.G1s(n),
		}
	})
}
