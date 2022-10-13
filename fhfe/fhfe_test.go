package fhfe

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestDecryptHardCoded(t *testing.T) {
	B, BStar, pp, _, g, gt, e := Setup(4)
	assert.NilError(t, e)

	x := pp.VectorZpFromInt([]int32{1, 1, 1, 1})
	y := pp.VectorZpFromInt([]int32{2, 2, 2, 2})

	ct, e := Encrypt(B, x, pp, g)
	assert.NilError(t, e)
	key, e := KeyGen(BStar, y, pp, g)
	assert.NilError(t, e)

	m, e := Decrypt(ct, key, pp, gt, pp.ZpFromInt(1), pp.ZpFromInt(10))
	assert.NilError(t, e)
	assert.Assert(t, m.EqualTo(pp.ZpFromInt(8)))
}

func TestDecryptRandom(t *testing.T) {
	B, BStar, pp, _, g, gt, e := Setup(10)
	assert.NilError(t, e)

	x := pp.VectorZpRandom(10)
	y := pp.VectorZpRandom(10)

	expected, e := x.InnerProduct(y)
	assert.NilError(t, e)

	from := expected.Add(pp.ZpFromInt(50).Negate())
	to := expected.Add(pp.ZpFromInt(50))

	ct, e := Encrypt(B, x, pp, g)
	assert.NilError(t, e)
	key, e := KeyGen(BStar, y, pp, g)
	assert.NilError(t, e)

	m, e := Decrypt(ct, key, pp, gt, from, to)
	assert.NilError(t, e)
	assert.Assert(t, m.EqualTo(expected))
}
