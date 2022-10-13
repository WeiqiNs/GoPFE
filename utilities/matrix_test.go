package utilities

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestMatrixZpFromInt(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2}, {3, 4}})
	assert.Assert(t, m.data[0][0].Is1())
}

func TestMatrix_NRow(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	assert.Assert(t, m.NRow() == 2)
}

func TestMatrix_NCol(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	assert.Assert(t, m.NCol() == 3)
}

func TestMatrix_String(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	expected := "\nMatrix 2 by 3\n[\n\t[1, 2, 3]\n\t[3, 4, 5]\n]\n"
	assert.Assert(t, m.String() == expected)
}

func TestMatricesEqual(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	mp := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	assert.Assert(t, m.EqualTo(mp))
}

func TestMatrixTranspose(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	expected := pp.MatrixZpFromInt([][]int32{{1, 3}, {2, 4}, {3, 5}})
	assert.Assert(t, expected.EqualTo(m.Transpose()))
}

func TestMatrixTimesConstant(t *testing.T) {
	pp := NewPairing()
	constant := pp.ZpFromInt(5)
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	expected := pp.MatrixZpFromInt([][]int32{{5, 10, 15}, {15, 20, 25}})
	assert.Assert(t, expected.EqualTo(m.TimesConstant(constant)))
}

func TestMatricesAdd(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	expected := pp.MatrixZpFromInt([][]int32{{2, 4, 6}, {6, 8, 10}})
	mm, e := m.Add(m)
	assert.Assert(t, e == nil)
	assert.Assert(t, expected.EqualTo(mm))
}

func TestMatricesMultiply(t *testing.T) {
	pp := NewPairing()
	l := pp.MatrixZpFromInt([][]int32{{1, 2, 3}, {3, 4, 5}})
	r := pp.MatrixZpFromInt([][]int32{{1, 3}, {2, 4}, {3, 5}})
	expected := pp.MatrixZpFromInt([][]int32{{14, 26}, {26, 50}})
	mm, e := l.Multiply(r)
	assert.Assert(t, e == nil)
	assert.Assert(t, expected.EqualTo(mm))
}

func TestMatrixIsIdentity(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpFromInt([][]int32{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}})
	assert.Assert(t, m.IsIdentity())

	m = pp.MatrixZpFromInt([][]int32{{1, 0, 1}, {0, 1, 0}, {0, 0, 1}})
	assert.Assert(t, !m.IsIdentity())

}

func TestMatrixInverse(t *testing.T) {
	pp := NewPairing()
	m := pp.MatrixZpRandom(10, 10)

	inverse, e := m.Inverse()
	assert.NilError(t, e)

	I, e := m.Multiply(inverse)
	assert.NilError(t, e)

	assert.Assert(t, I.IsIdentity())
}
