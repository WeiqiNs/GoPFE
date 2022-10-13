package utilities

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestVectorExpand(t *testing.T) {
	pp := NewPairing()
	v := pp.VectorZpFromInt([]int32{1, 2, 3, 4})
	expanded, e := v.Expand(pp.ZpFromInt(5), pp.ZpFromInt(6))
	assert.NilError(t, e)

	expected := pp.VectorZpFromInt([]int32{1, 2, 3, 4, 5, 6})
	equal, e := expected.EqualTo(expanded)
	assert.NilError(t, e)
	assert.Assert(t, equal)
}

func TestVectorMerge(t *testing.T) {
	pp := NewPairing()
	m := pp.VectorZpFromInt([]int32{1, 2, 3})
	n := pp.VectorZpFromInt([]int32{4, 5, 6})

	merged, e := m.Merge(n)
	assert.NilError(t, e)

	expected := pp.VectorZpFromInt([]int32{1, 2, 3, 4, 5, 6})
	equal, e := expected.EqualTo(merged)
	assert.NilError(t, e)
	assert.Assert(t, equal)
}

func TestMultiplyVectors(t *testing.T) {
	pp := NewPairing()
	m := pp.VectorZpFromInt([]int32{1, 2, 3})
	n := pp.VectorZpFromInt([]int32{2, 4, 6})

	mn, e := m.InnerProduct(n)
	assert.NilError(t, e)

	expected := pp.ZpFromInt(28)
	assert.Assert(t, expected.EqualTo(mn))
}

func TestVectorsAdd(t *testing.T) {
	pp := NewPairing()
	m := pp.VectorZpFromInt([]int32{1, 2, 3})
	n := pp.VectorZpFromInt([]int32{2, 4, 6})

	mn, e := m.Add(n)
	assert.NilError(t, e)

	expected := pp.VectorZpFromInt([]int32{3, 6, 9})
	equal, e := expected.EqualTo(mn)
	assert.NilError(t, e)
	assert.Assert(t, equal)
}

func TestVectorMultiplyMatrix(t *testing.T) {
	pp := NewPairing()
	v := pp.VectorZpFromInt([]int32{7, 8})
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})

	vm, e := v.TimesMatrix(m)
	assert.NilError(t, e)

	expected := pp.VectorZpFromInt([]int32{31, 46, 61})
	equal, e := expected.EqualTo(vm)
	assert.NilError(t, e)
	assert.Assert(t, equal)
}
