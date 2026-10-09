package kks

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n      int
	eta    group.Zp
	etaBar group.Zp
	s      group.Vector
	t      group.Vector
	u      group.Vector
	v      group.Vector
	h      group.Vector
	hHat   group.Vector
	hBar   group.Vector
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
	eta, etaBar := group.RandomZp(), group.RandomZp()
	s, t := group.RandomVector(n), group.RandomVector(n)
	u, v := group.RandomVector(n+2), group.RandomVector(n+2)
	return MasterKey{
		n:      n,
		eta:    eta,
		etaBar: etaBar,
		s:      s,
		t:      t,
		u:      u,
		v:      v,
		h:      s.Plus(t.Scale(eta)),
		hHat:   group.RandomVector(n).Plus(group.RandomVector(n).Scale(eta)),
		hBar:   u.Plus(v.Scale(etaBar)),
	}, nil
}

func Base() group.GT {
	return group.GTGenerator()
}

func ciphertextHalf(msk MasterKey, h, m group.Vector) group.Vector {
	r := group.RandomZp()
	ct1 := group.Concat(group.Vector{r, group.Mul(msk.eta, r)}, m.Plus(h.Scale(r)))
	return group.Concat(group.Vector{group.Neg(group.Inner(msk.u, ct1)), group.Neg(group.Inner(msk.v, ct1))}, ct1)
}

func keyHalf(msk MasterKey, key group.Vector) group.Vector {
	r := group.RandomZp()
	return group.Concat(group.Vector{r, group.Mul(msk.etaBar, r)}, key.Plus(msk.hBar.Scale(r)))
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	key := group.Concat(group.Vector{group.Neg(group.Inner(msk.s, f)), group.Neg(group.Inner(msk.t, f))}, f)
	return Key{n: msk.n, vec: group.G2MulVec(group.Concat(keyHalf(msk, key), keyHalf(msk, group.Zeros(len(key)))))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.n)
	if err != nil {
		return Ciphertext{}, err
	}
	return Ciphertext{
		n:   msk.n,
		vec: group.G1MulVec(group.Concat(ciphertextHalf(msk, msk.h, m), ciphertextHalf(msk, msk.hHat, m))),
	}, nil
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
	return group.NewEncoder(msk.n).Zp(msk.eta).Zp(msk.etaBar).Vector(msk.s).Vector(msk.t).Vector(msk.u).Vector(msk.v).
		Vector(msk.h).Vector(msk.hHat).Vector(msk.hBar).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n:      n,
			eta:    dec.Zp(),
			etaBar: dec.Zp(),
			s:      dec.Vector(n),
			t:      dec.Vector(n),
			u:      dec.Vector(n + 2),
			v:      dec.Vector(n + 2),
			h:      dec.Vector(n),
			hHat:   dec.Vector(n),
			hBar:   dec.Vector(n + 2),
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
			vec: dec.G2s(2*n + 8),
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
			vec: dec.G1s(2*n + 8),
		}
	})
}
