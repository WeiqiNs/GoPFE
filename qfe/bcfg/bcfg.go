package bcfg

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N int
	W group.Zp
	A group.Vector
	B group.Vector
}

type PublicKey struct {
	N int
	A []group.G1
	B []group.G2
	W group.G2
}

type Key struct {
	F  group.Matrix
	S1 group.G1
	S2 group.G1
	AF []group.G1
	FB []group.G2
}

type Ciphertext struct {
	C    []group.G1
	CHat []group.G1
	D    []group.G2
	DHat []group.G2
	E    group.G2
	EHat group.G2
}

type PreparedKey struct {
	Key Key
	FB  group.Prepared
}

type DecryptionKey interface {
	Key | PreparedKey
	split() (Key, group.G2Side)
}

func Setup(n int) (PublicKey, MasterKey) {
	w := group.RandomZp()
	a, b := group.RandomVector(n), group.RandomVector(n)
	pk := PublicKey{N: n, A: group.G1MulVec(a), B: group.G2MulVec(b), W: group.G2Mul(w)}
	return pk, MasterKey{N: n, W: w, A: a, B: b}
}

func Base() group.GT {
	return group.GTGenerator()
}

func KeyGen(msk MasterKey, function [][]int64) (Key, error) {
	f, err := group.IntMatrix(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	gamma := group.RandomZp()
	fb := f.MulVec(msk.B)
	return Key{
		F:  f,
		S1: group.G1Mul(group.Add(group.Inner(msk.A, fb), group.Mul(gamma, msk.W))),
		S2: group.G1Mul(gamma),
		AF: group.G1MulVec(msk.A.MulMat(f)),
		FB: group.G2MulVec(fb),
	}, nil
}

func Encrypt(pk PublicKey, left, right []int64) (Ciphertext, error) {
	x, err := group.IntVector(left, pk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	y, err := group.IntVector(right, pk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	r, s, t, z := group.RandomZp(), group.RandomZp(), group.RandomZp(), group.RandomZp()
	blind := group.Sub(group.Sub(group.Mul(r, s), z), t)
	return Ciphertext{
		C:    group.MaskedG1(pk.A, r, x),
		CHat: group.MaskedG1(pk.A, t, x.Scale(s)),
		D:    group.MaskedG2(pk.B, s, y),
		DHat: group.MaskedG2(pk.B, z, y.Scale(r)),
		E:    group.G2Mul(blind),
		EHat: group.ScaleG2(pk.W, blind),
	}, nil
}

func Prepare(sk Key) PreparedKey {
	return PreparedKey{Key: sk, FB: group.Prepare(sk.FB)}
}

func Decrypt[K DecryptionKey](table *group.DlogTable, sk K, ct Ciphertext) (int64, bool) {
	key, fb := sk.split()
	var e group.PairingProduct
	e.MulBilinear(ct.C, key.F, ct.D)
	e.Div(key.AF, group.Affine(ct.DHat))
	e.Div(ct.CHat, fb)
	e.Div([]group.G1{key.S1}, group.Affine{ct.E})
	e.Mul([]group.G1{key.S2}, group.Affine{ct.EHat})
	return table.Find(e.Value())
}

func (sk Key) split() (Key, group.G2Side) {
	return sk, group.Affine(sk.FB)
}

func (sk PreparedKey) split() (Key, group.G2Side) {
	return sk.Key, sk.FB
}
