package ipe

import (
	"fmt"

	"git.dbogatov.org/bu/ipfre/scheme/fhfe"
	u "git.dbogatov.org/bu/ipfre/scheme/utilities"
)

type LookupTable map[string]int32

func Setup(n int) (A u.Matrix, B u.Matrix, BStar u.Matrix, pp u.Pairing, phi u.Element, g u.Element, gt u.Element, e error) {
	// Run function-hiding FE's setup to get public parameters.
	B, BStar, pp, phi, g, gt, e = fhfe.Setup(4)
	if e != nil {
		return
	}

	// We may remove the label in the scheme, then we will keep using the same A for encryption.
	A = pp.MatrixZpRandom(2, n)
	return
}

func Encrypt(message u.Vector, A u.Matrix, B u.Matrix, BStar u.Matrix, pp u.Pairing, g u.Element) (ctx u.Vector, ctc u.Vector, ctk u.Vector, e error) {
	// Sample a fresh s.
	s := pp.VectorZpRandom(2)

	// Encrypt the message with sA.
	sA, e := s.TimesMatrix(A)
	if e != nil {
		return
	}
	sAx, e := sA.Add(message)
	if e != nil {
		return
	}
	ctx, e = sAx.Power(g)
	if e != nil {
		return
	}

	// Call the function-hiding FE's Enc.
	AT := A.Transpose()
	xAT, e := message.TimesMatrix(AT)
	if e != nil {
		return
	}
	v, e := xAT.Merge(s)
	if e != nil {
		return
	}

	ctc, e = fhfe.Encrypt(B, v, pp, g)
	if e != nil {
		return
	}

	// Call the function-hiding FE's Keygen.
	sAAT, e := sA.TimesMatrix(AT)
	if e != nil {
		return
	}
	xATsAAT, e := xAT.Add(sAAT)
	if e != nil {
		return
	}
	w, e := s.Merge(xATsAAT)
	if e != nil {
		return
	}
	ctk, e = fhfe.KeyGen(BStar, w, pp, g)

	return
}

func EvalWithRange(ctx1 u.Vector, ctc1 u.Vector, ctx2 u.Vector, ctk2 u.Vector, pp u.Pairing, phi u.Element, gt u.Element, from u.Element, to u.Element) (m u.Element, e error) {
	xy, e := pp.PairVectors(ctx1, ctx2)
	if e != nil {
		return
	}

	cross, e := pp.PairVectors(ctc1, ctk2)
	if e != nil {
		return
	}

	xy = xy.Power(phi).Add(cross.Inverse())

	one := pp.ZpOne()
	for m = from; !m.EqualTo(to); m = m.Add(one) {
		if gt.Power(m).EqualTo(xy) {
			return
		}
	}

	e = fmt.Errorf("no plaintext found in range")

	return
}

func EvalWithTable(ctx1 u.Vector, ctc1 u.Vector, ctx2 u.Vector, ctk2 u.Vector, pp u.Pairing, phi u.Element, table *LookupTable) (m int32, e error) {
	xy, e := pp.PairVectors(ctx1, ctx2)
	if e != nil {
		return
	}

	cross, e := pp.PairVectors(ctc1, ctk2)
	if e != nil {
		return
	}

	xy = xy.Power(phi).Add(cross.Inverse())

	m, found := (*table)[string(xy.ToBytes())]

	if !found {
		e = fmt.Errorf("no plaintext found in range")
	}

	return
}

func GenerateLookupTable(pp u.Pairing, gt u.Element, from int32, to int32, table *LookupTable) {
	*table = make(map[string]int32)

	e := pp.NewGT().Set0()

	for m := from; m < to; m++ {
		e = e.ThenAdd(gt.Element)
		(*table)[string(e.Bytes())] = m
	}

}
