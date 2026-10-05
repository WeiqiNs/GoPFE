package kks

import "github.com/WeiqiNs/GoPFE/group"

type MasterKey struct {
	N      int
	Eta    group.Zp
	EtaBar group.Zp
	S      group.Vector
	T      group.Vector
	U      group.Vector
	V      group.Vector
	H      group.Vector
	HHat   group.Vector
	HBar   group.Vector
}

type Key struct {
	Vec []group.G2
}

type Ciphertext struct {
	Vec []group.G1
}

func Setup(n int) MasterKey {
	eta, etaBar := group.RandomZp(), group.RandomZp()
	s, t := group.RandomVector(n), group.RandomVector(n)
	u, v := group.RandomVector(n+2), group.RandomVector(n+2)
	return MasterKey{
		N:      n,
		Eta:    eta,
		EtaBar: etaBar,
		S:      s,
		T:      t,
		U:      u,
		V:      v,
		H:      s.Plus(t.Scale(eta)),
		HHat:   group.RandomVector(n).Plus(group.RandomVector(n).Scale(eta)),
		HBar:   u.Plus(v.Scale(etaBar)),
	}
}

func Base() group.GT {
	return group.GTGenerator()
}

func ciphertextHalf(msk MasterKey, h, m group.Vector) group.Vector {
	r := group.RandomZp()
	ct1 := group.Concat(group.Vector{r, group.Mul(msk.Eta, r)}, m.Plus(h.Scale(r)))
	return group.Concat(group.Vector{group.Neg(group.Inner(msk.U, ct1)), group.Neg(group.Inner(msk.V, ct1))}, ct1)
}

func keyHalf(msk MasterKey, key group.Vector) group.Vector {
	r := group.RandomZp()
	return group.Concat(group.Vector{r, group.Mul(msk.EtaBar, r)}, key.Plus(msk.HBar.Scale(r)))
}

func KeyGen(msk MasterKey, function []int64) (Key, error) {
	f, err := group.IntVector(function, msk.N)
	if err != nil {
		return Key{}, err
	}
	key := group.Concat(group.Vector{group.Neg(group.Inner(msk.S, f)), group.Neg(group.Inner(msk.T, f))}, f)
	return Key{Vec: group.G2MulVec(group.Concat(keyHalf(msk, key), keyHalf(msk, group.Zeros(len(key)))))}, nil
}

func Encrypt(msk MasterKey, message []int64) (Ciphertext, error) {
	m, err := group.IntVector(message, msk.N)
	if err != nil {
		return Ciphertext{}, err
	}
	return Ciphertext{Vec: group.G1MulVec(group.Concat(ciphertextHalf(msk, msk.H, m), ciphertextHalf(msk, msk.HHat, m)))}, nil
}

func Decrypt(table *group.DlogTable, sk Key, ct Ciphertext) (int64, bool) {
	return decrypt(table, group.Affine(sk.Vec), ct)
}

func DecryptMany(table *group.DlogTable, sk Key, cts []Ciphertext) []group.Decryption {
	vec := group.Prepare(sk.Vec)
	return group.DecryptEach(cts, func(ct Ciphertext) (int64, bool) { return decrypt(table, vec, ct) })
}

func decrypt(table *group.DlogTable, vec group.G2Side, ct Ciphertext) (int64, bool) {
	return table.Find(group.Pair(ct.Vec, vec))
}
