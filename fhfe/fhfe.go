package fhfe

import (
	"fmt"

	u "git.dbogatov.org/bu/ipfre/scheme/utilities"
)

func generateCiphertext(M u.Matrix, message u.Vector, extras []u.Element, g u.Element) (output u.Vector, e error) {
	fullMessage, e := message.Expand(extras...)
	if e != nil {
		return
	}

	randomizedMessage, e := fullMessage.TimesMatrix(M)
	if e != nil {
		return
	}

	output, e = randomizedMessage.Power(g)
	return
}

func Setup(n int) (B u.Matrix, BStar u.Matrix, pp u.Pairing, phi u.Element, g u.Element, gt u.Element, e error) {

	pp = u.NewPairing()
	B = pp.MatrixZpRandom(n+4, n+4)

	BInverse, e := B.Inverse()
	BTransposeInverse := BInverse.Transpose()
	phi = pp.RandomZp()
	BStar = BTransposeInverse.TimesConstant(phi)

	g = pp.RandomPoint()
	gt = pp.Pair(g, g).Power(phi)

	return
}

func Encrypt(B u.Matrix, message u.Vector, pp u.Pairing, g u.Element) (ciphertext u.Vector, e error) {

	zero := pp.ZpZero()
	alpha := pp.RandomZp()
	eta := pp.RandomZp()

	return generateCiphertext(B, message, []u.Element{alpha, eta, zero, zero}, g)
}

func KeyGen(BStar u.Matrix, message u.Vector, pp u.Pairing, g u.Element) (ciphertext u.Vector, e error) {
	zero := pp.ZpZero()
	beta := pp.RandomZp()
	omega := pp.RandomZp()

	return generateCiphertext(BStar, message, []u.Element{zero, zero, beta, omega}, g)
}

func Decrypt(ct u.Vector, key u.Vector, pp u.Pairing, gt u.Element, from u.Element, to u.Element) (m u.Element, e error) {
	d, e := pp.PairVectors(ct, key)
	if e != nil {
		return
	}

	one := pp.ZpOne()
	for m = from; !m.EqualTo(to); m = m.Add(one) {
		if gt.Power(m).EqualTo(d) {
			return
		}
	}

	e = fmt.Errorf("no plaintext found in range")

	return
}
