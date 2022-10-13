package utilities

import (
	"git.dbogatov.org/bu/ipfre/pbc-go"
)

type Element struct {
	*pbc.Element
}

type Pairing struct {
	*pbc.Pairing
}

func NewPairing() (result Pairing) {
	result = Pairing{pbc.GenerateA(160, 512).NewPairing()}
	return
}

func (pp Pairing) RandomPoint() (result Element) {
	result = Element{pp.NewG1().Rand()}
	return
}

func (pp Pairing) Pair(x Element, y Element) (result Element) {
	result = Element{pp.NewGT()}
	result.Pair(x.Element, y.Element)
	return
}

func (pp Pairing) RandomZp() (result Element) {
	result = Element{pp.NewZr().Rand()}
	return
}

func (pp Pairing) ZpFromInt(x int32) (result Element) {
	return Element{pp.NewZr().SetInt32(x)}
}

func (pp Pairing) ZpZero() (result Element) {
	return pp.ZpFromInt(0)
}

func (pp Pairing) ZpOne() (result Element) {
	return pp.ZpFromInt(1)
}

func (e Element) ToBytes() (bytes []byte) {
	bytes = e.Element.Bytes()

	return
}

func (e Element) Copy() (result Element) {
	return Element{e.NewFieldElement().Set(e.Element)}
}

func (e Element) EqualTo(y Element) (result bool) {
	result = e.Element.Equals(y.Element)
	return
}

func (e Element) Add(y Element) (result Element) {
	result = Element{e.NewFieldElement()}
	result.Element.Add(e.Element, y.Element)
	return
}

func (e Element) Multiply(y Element) (result Element) {
	result = Element{e.NewFieldElement()}
	result.Element.MulZn(e.Element, y.Element)
	return
}

func (e Element) Power(y Element) (result Element) {
	return e.Multiply(y) // note that PBC will do multiplication differently for Zp and Points
}

func (e Element) Negate() (result Element) {
	result = Element{e.NewFieldElement().Set(e.Element).ThenNeg()}
	return
}

func (e Element) Inverse() (result Element) {
	result = Element{e.NewFieldElement().Set(e.Element).ThenInvert()}
	return
}

func (e Element) Zero() (result Element) {
	result = Element{e.NewFieldElement().Set0()}
	return
}

func (e Element) One() (result Element) {
	result = Element{e.NewFieldElement().Set1()}
	return
}

func (e Element) IsZero() (result bool) {
	result = e.Element.Is0()
	return
}

func (e Element) IsOne() (result bool) {
	result = e.Element.Is1()
	return
}
