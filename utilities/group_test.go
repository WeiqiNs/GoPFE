package utilities

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestCopy(t *testing.T) {
	pp := NewPairing()

	// Set one and copy one.
	one := pp.ZpFromInt(1)
	oneCopy := one.Copy()

	// Change one to make sure the copy is not changed.
	one.SetInt32(10)
	assert.Assert(t, !oneCopy.EqualTo(one))
}

func TestInt(t *testing.T) {
	pp := NewPairing()

	// Set one.
	one := pp.ZpFromInt(1)
	assert.Assert(t, one.String() == "1")
}

func TestAdd(t *testing.T) {
	pp := NewPairing()

	a := pp.ZpFromInt(1)
	b := pp.ZpFromInt(2)
	c := pp.ZpFromInt(3)
	r := a.Add(b)

	assert.Assert(t, c.EqualTo(r))
}

func TestMultiply(t *testing.T) {
	pp := NewPairing()

	a := pp.ZpFromInt(1)
	b := pp.ZpFromInt(2)
	r := a.Multiply(b)

	assert.Assert(t, b.EqualTo(r))
}

func TestPair(t *testing.T) {
	pp := NewPairing()

	g := pp.RandomPoint()
	gt := pp.Pair(g, g)

	expected := pp.NewGT()
	expected.Pair(g.Element, g.Element)

	assert.Assert(t, gt.Equals(expected))
}

func TestElement_Power(t *testing.T) {
	pp := NewPairing()

	a := Element{pp.NewG1().Rand()}
	b := pp.ZpFromInt(10)
	r := a.Power(b)

	rp := a.NewFieldElement()
	rp.MulZn(a.Element, b.Element)

	assert.Assert(t, r.Equals(rp))
}

func TestElement_Negate(t *testing.T) {
	pp := NewPairing()

	a := pp.ZpFromInt(10)
	an := a.Negate()

	assert.Assert(t, a.Add(an).IsZero())
}

func TestElement_Inverse(t *testing.T) {
	pp := NewPairing()

	a := pp.ZpFromInt(10)
	an := a.Inverse()

	assert.Assert(t, a.Multiply(an).IsOne())
}

func TestElement_Zero(t *testing.T) {
	pp := NewPairing()

	a := pp.ZpFromInt(10)
	assert.Assert(t, a.Zero().IsZero())
}

func TestElement_One(t *testing.T) {
	pp := NewPairing()

	a := pp.ZpFromInt(10)
	assert.Assert(t, a.One().IsOne())
}

func TestZpZero(t *testing.T) {
	pp := NewPairing()
	assert.Assert(t, pp.ZpZero().IsZero())
}

func TestZpOne(t *testing.T) {
	pp := NewPairing()
	assert.Assert(t, pp.ZpOne().IsOne())
}
