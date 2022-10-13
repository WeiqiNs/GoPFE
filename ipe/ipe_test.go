package ipe

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestDecryptHardCoded(t *testing.T) {
	A, B, BStar, pp, phi, g, gt, e := Setup(4)
	assert.NilError(t, e)

	x := pp.VectorZpFromInt([]int32{1, 2, 3, 4})
	y := pp.VectorZpFromInt([]int32{5, 6, 7, 8})

	ctx1, ctc1, _, e := Encrypt(x, A, B, BStar, pp, g)
	assert.NilError(t, e)
	ctx2, _, ctk2, e := Encrypt(y, A, B, BStar, pp, g)
	assert.NilError(t, e)

	m, e := EvalWithRange(ctx1, ctc1, ctx2, ctk2, pp, phi, gt, pp.ZpFromInt(1), pp.ZpFromInt(100))
	assert.NilError(t, e)

	assert.Assert(t, m.EqualTo(pp.ZpFromInt(70)))
}

func TestDecryptLookupHardCoded(t *testing.T) {
	A, B, BStar, pp, phi, g, gt, e := Setup(4)
	assert.NilError(t, e)

	x := pp.VectorZpFromInt([]int32{1, 2, 3, 4})
	y := pp.VectorZpFromInt([]int32{5, 6, 7, 8})

	ctx1, ctc1, _, e := Encrypt(x, A, B, BStar, pp, g)
	assert.NilError(t, e)
	ctx2, _, ctk2, e := Encrypt(y, A, B, BStar, pp, g)
	assert.NilError(t, e)

	var table LookupTable
	GenerateLookupTable(pp, gt, int32(1), int32(100), &table)

	m, e := EvalWithTable(ctx1, ctc1, ctx2, ctk2, pp, phi, &table)
	assert.NilError(t, e)

	assert.Assert(t, m == int32(70))
}

func TestDecryptRandom(t *testing.T) {
	size := 768

	A, B, BStar, pp, phi, g, gt, e := Setup(size)
	assert.NilError(t, e)

	x := pp.VectorZpRandom(size)
	y := pp.VectorZpRandom(size)

	expected, e := x.InnerProduct(y)
	assert.NilError(t, e)

	from := expected.Add(pp.ZpFromInt(50).Negate())
	to := expected.Add(pp.ZpFromInt(50))

	ctx1, ctc1, _, e := Encrypt(x, A, B, BStar, pp, g)
	assert.NilError(t, e)
	ctx2, _, ctk2, e := Encrypt(y, A, B, BStar, pp, g)
	assert.NilError(t, e)

	m, e := EvalWithRange(ctx1, ctc1, ctx2, ctk2, pp, phi, gt, from, to)
	assert.NilError(t, e)
	assert.Assert(t, m.EqualTo(expected))
}
