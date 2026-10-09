package bcfg

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	n int
	w group.Zp
	a group.Vector
	b group.Vector
}

type PublicKey struct {
	n int
	a []group.G1
	b []group.G2
	w group.G2
}

type Key struct {
	n  int
	f  group.Matrix
	s1 group.G1
	s2 group.G1
	af []group.G1
	fb []group.G2
}

type Ciphertext struct {
	n    int
	c    []group.G1
	cHat []group.G1
	d    []group.G2
	dHat []group.G2
	e    group.G2
	eHat group.G2
}

type PreparedKey struct {
	key Key
	fb  group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	split() (Key, group.G2Side)
}

func Setup(n int) (PublicKey, MasterKey, error) {
	if err := group.CheckDimension(n); err != nil {
		return PublicKey{}, MasterKey{}, err
	}
	w := group.RandomZp()
	a, b := group.RandomVector(n), group.RandomVector(n)
	pk := PublicKey{n: n, a: group.G1MulVec(a), b: group.G2MulVec(b), w: group.G2Mul(w)}
	return pk, MasterKey{n: n, w: w, a: a, b: b}, nil
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function [][]int64) (Key, error) {
	f, err := group.IntMatrix(function, msk.n)
	if err != nil {
		return Key{}, err
	}
	gamma := group.RandomZp()
	fb := f.MulVec(msk.b)
	return Key{
		n:  msk.n,
		f:  f,
		s1: group.G1Mul(group.Add(group.Inner(msk.a, fb), group.Mul(gamma, msk.w))),
		s2: group.G1Mul(gamma),
		af: group.G1MulVec(msk.a.MulMat(f)),
		fb: group.G2MulVec(fb),
	}, nil
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
	r, s, t, z := group.RandomZp(), group.RandomZp(), group.RandomZp(), group.RandomZp()
	blind := group.Sub(group.Sub(group.Mul(r, s), z), t)
	return Ciphertext{
		n:    pk.n,
		c:    group.MaskedG1(pk.a, r, x),
		cHat: group.MaskedG1(pk.a, t, x.Scale(s)),
		d:    group.MaskedG2(pk.b, s, y),
		dHat: group.MaskedG2(pk.b, z, y.Scale(r)),
		e:    group.G2Mul(blind),
		eHat: group.ScaleG2(pk.w, blind),
	}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{key: sk, fb: group.Prepare(sk.fb)}
}

func Decrypt[K DecryptionKey](table *group.DlogTable, sk K, ct Ciphertext) (int64, bool) {
	key, fb := sk.split()
	var e group.PairingProduct
	e.MulBilinear(ct.c, key.f, ct.d)
	e.Div(key.af, group.Affine(ct.dHat))
	e.Div(ct.cHat, fb)
	e.Div([]group.G1{key.s1}, group.Affine{ct.e})
	e.Mul([]group.G1{key.s2}, group.Affine{ct.eHat})
	return table.Find(e.Value())
}

func (sk Key) split() (Key, group.G2Side) {
	return sk, group.Affine(sk.fb)
}

func (sk PreparedKey) split() (Key, group.G2Side) {
	return sk.key, sk.fb
}

func (msk MasterKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(msk.n).Zp(msk.w).Vector(msk.a).Vector(msk.b).Bytes(), nil
}

func (msk *MasterKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, msk, func(dec *group.Decoder, n int) MasterKey {
		return MasterKey{
			n: n,
			w: dec.Zp(),
			a: dec.Vector(n),
			b: dec.Vector(n),
		}
	})
}

func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(pk.n).G1s(pk.a).G2s(pk.b).G2(pk.w).Bytes(), nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	return group.Decode(data, pk, func(dec *group.Decoder, n int) PublicKey {
		return PublicKey{
			n: n,
			a: dec.G1s(n),
			b: dec.G2s(n),
			w: dec.G2(),
		}
	})
}

func (sk Key) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(sk.n).Matrix(sk.f).G1(sk.s1).G1(sk.s2).G1s(sk.af).G2s(sk.fb).Bytes(), nil
}

func (sk *Key) UnmarshalBinary(data []byte) error {
	return group.Decode(data, sk, func(dec *group.Decoder, n int) Key {
		return Key{
			n:  n,
			f:  dec.Matrix(n, n),
			s1: dec.G1(),
			s2: dec.G1(),
			af: dec.G1s(n),
			fb: dec.G2s(n),
		}
	})
}

func (ct Ciphertext) MarshalBinary() ([]byte, error) {
	return group.NewEncoder(ct.n).G1s(ct.c).G1s(ct.cHat).G2s(ct.d).G2s(ct.dHat).G2(ct.e).G2(ct.eHat).Bytes(), nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	return group.Decode(data, ct, func(dec *group.Decoder, n int) Ciphertext {
		return Ciphertext{
			n:    n,
			c:    dec.G1s(n),
			cHat: dec.G1s(n),
			d:    dec.G2s(n),
			dHat: dec.G2s(n),
			e:    dec.G2(),
			eHat: dec.G2(),
		}
	})
}
