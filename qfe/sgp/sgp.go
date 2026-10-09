package sgp

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n int
	s group.Vector
	t group.Vector
}

type PublicKey struct {
	n int
	s []group.G1
	t []group.G2
}

type Key struct {
	n      int
	f      group.Matrix
	secret group.G2
}

type Ciphertext struct {
	n     int
	gamma group.G1
	a0    []group.G1
	a1    []group.G1
	b0    []group.G2
	b1    []group.G2
}

type PreparedKey struct {
	f      group.Matrix
	secret group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	split() (group.Matrix, group.G2Side)
}

func Setup(n int) (PublicKey, MasterKey, error) {
	if err := group.CheckDimension(n); err != nil {
		return PublicKey{}, MasterKey{}, err
	}
	s, t := group.RandomVector(n), group.RandomVector(n)
	return PublicKey{n: n, s: group.G1MulVec(s), t: group.G2MulVec(t)}, MasterKey{n: n, s: s, t: t}, nil
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function [][]int64) (Key, error) {
	f, err := group.IntMatrix(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	return Key{n: msk.n, f: f, secret: group.G2Mul(group.Inner(msk.s, f.MulVec(msk.t)))}, nil
}

func Encrypt(pk PublicKey, left, right []int64) (Ciphertext, error) {
	x, err := group.IntVector(left, pk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	y, err := group.IntVector(right, pk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	gamma := group.RandomZp()
	w, inverse, _ := group.RandomInvertible(2)
	wi := inverse.Transpose()
	return Ciphertext{
		n:     pk.n,
		gamma: group.G1Mul(gamma),
		a0:    group.MaskedG1(pk.s, group.Mul(gamma, wi.At(0, 1)), x.Scale(wi.At(0, 0))),
		a1:    group.MaskedG1(pk.s, group.Mul(gamma, wi.At(1, 1)), x.Scale(wi.At(1, 0))),
		b0:    group.MaskedG2(pk.t, group.Neg(w.At(0, 1)), y.Scale(w.At(0, 0))),
		b1:    group.MaskedG2(pk.t, group.Neg(w.At(1, 1)), y.Scale(w.At(1, 0))),
	}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{f: sk.f, secret: group.Prepare([]group.G2{sk.secret})}
}

func Decrypt[K DecryptionKey](table *group.DlogTable, sk K, ct Ciphertext) (int64, bool) {
	f, secret := sk.split()
	var e group.PairingProduct
	e.Mul([]group.G1{ct.gamma}, secret)
	e.MulBilinear(ct.a0, f, ct.b0)
	e.MulBilinear(ct.a1, f, ct.b1)
	return table.Find(e.Value())
}

func (sk Key) split() (group.Matrix, group.G2Side) {
	return sk.f, group.Affine{sk.secret}
}

func (sk PreparedKey) split() (group.Matrix, group.G2Side) {
	return sk.f, sk.secret
}

func (msk MasterKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(msk.n).Vector(msk.s).Vector(msk.t).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n: n,
			s: dec.Vector(n),
			t: dec.Vector(n),
		}
	})
}

func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(pk.n).G1s(pk.s).G2s(pk.t).Bytes(), nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, pk, func(dec *group.Decoder, n int) PublicKey {
		return PublicKey{
			n: n,
			s: dec.G1s(n),
			t: dec.G2s(n),
		}
	})
}

func (sk Key) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(sk.n).Matrix(sk.f).G2(sk.secret).Bytes(), nil
}

func (sk *Key) UnmarshalBinary(data []byte) error {
	return group.Decode(data, sk, func(dec *group.Decoder, n int) Key {
		return Key{
			n:      n,
			f:      dec.Matrix(n, n),
			secret: dec.G2(),
		}
	})
}

func (ct Ciphertext) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(ct.n).G1(ct.gamma).G1s(ct.a0).G1s(ct.a1).G2s(ct.b0).G2s(ct.b1).Bytes(), nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	return group.Decode(data, ct, func(dec *group.Decoder, n int) Ciphertext {
		return Ciphertext{
			n:     n,
			gamma: dec.G1(),
			a0:    dec.G1s(n),
			a1:    dec.G1s(n),
			b0:    dec.G2s(n),
			b1:    dec.G2s(n),
		}
	})
}
