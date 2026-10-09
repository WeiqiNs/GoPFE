package group

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var ErrShape = errors.New("group: input has the wrong shape")

const rowsPerTask = 32

type Vector []Zp

type Matrix struct {
	rows, cols int
	data       fr.Vector
}

func mustMatch(a, b int) {
	if a != b {
		panic(fmt.Sprintf("group: lengths %d and %d differ", a, b))
	}
}

func Zeros(n int) Vector {
	return make(Vector, n)
}

func RandomVector(n int) Vector {
	v := make(Vector, n)
	fr.Vector(v).MustSetRandom()
	return v
}

func IntVector(xs []int64, n int) (Vector, error) {
	if len(xs) != n {
		return nil, fmt.Errorf("%w: got %d entries, want %d", ErrShape, len(xs), n)
	}
	v := make(Vector, n)
	for i, x := range xs {
		v[i] = NewZp(x)
	}
	return v, nil
}

func Concat(vs ...Vector) Vector {
	return slices.Concat(vs...)
}

func (v Vector) Plus(w Vector) Vector {
	mustMatch(len(v), len(w))
	r := make(fr.Vector, len(v))
	r.Add(fr.Vector(v), fr.Vector(w))
	return Vector(r)
}

func (v Vector) Scale(k Zp) Vector {
	r := make(fr.Vector, len(v))
	r.ScalarMul(fr.Vector(v), &k)
	return Vector(r)
}

func Inner(v, w Vector) Zp {
	mustMatch(len(v), len(w))
	return (*fr.Vector)(&v).InnerProduct(fr.Vector(w))
}

func NewMatrix(rows, cols int) Matrix {
	return Matrix{rows: rows, cols: cols, data: make(fr.Vector, rows*cols)}
}

func RandomMatrix(rows, cols int) Matrix {
	m := NewMatrix(rows, cols)
	m.data.MustSetRandom()
	return m
}

func IntMatrix(rows [][]int64, n int) (Matrix, error) {
	if len(rows) != n {
		return Matrix{}, fmt.Errorf("%w: got %d rows, want %d", ErrShape, len(rows), n)
	}
	m := NewMatrix(n, n)
	for i, row := range rows {
		v, err := IntVector(row, n)
		if err != nil {
			return Matrix{}, err
		}
		copy(m.row(i), v)
	}
	return m, nil
}

func RandomInvertible(n int) (m, inverse Matrix, det Zp) {
	for {
		m = RandomMatrix(n, n)
		if inverse, det, ok := m.invert(); ok {
			return m, inverse, det
		}
	}
}

func (m Matrix) At(i, j int) Zp { return m.data[i*m.cols+j] }

func (m Matrix) set(i, j int, z Zp) { m.data[i*m.cols+j] = z }

func (m Matrix) row(i int) fr.Vector { return m.data[i*m.cols : (i+1)*m.cols] }

func (m Matrix) Column(j int) Vector {
	v := make(Vector, m.rows)
	for i := range v {
		v[i] = m.At(i, j)
	}
	return v
}

func (m Matrix) Transpose() Matrix {
	t := NewMatrix(m.cols, m.rows)
	for i := range m.rows {
		for j := range m.cols {
			t.set(j, i, m.At(i, j))
		}
	}
	return t
}

func (m Matrix) Scale(k Zp) Matrix {
	r := NewMatrix(m.rows, m.cols)
	r.data.ScalarMul(m.data, &k)
	return r
}

func (m Matrix) MulVec(v Vector) Vector {
	mustMatch(m.cols, len(v))
	r := make(Vector, m.rows)
	for i := range r {
		r[i] = Inner(Vector(m.row(i)), v)
	}
	return r
}

func (v Vector) MulMat(m Matrix) Vector {
	mustMatch(len(v), m.rows)
	r, scaled := make(fr.Vector, m.cols), make(fr.Vector, m.cols)
	for i := range v {
		scaled.ScalarMul(m.row(i), &v[i])
		r.Add(r, scaled)
	}
	return Vector(r)
}

func (m Matrix) invert() (Matrix, Zp, bool) {
	n := m.rows
	work := NewMatrix(n, 2*n)
	for i := range n {
		copy(work.row(i), m.row(i))
		work.set(i, n+i, NewZp(1))
	}
	det := NewZp(1)
	for col := range n {
		pivot := col
		for pivot < n {
			if entry := work.At(pivot, col); !entry.IsZero() {
				break
			}
			pivot++
		}
		if pivot == n {
			return Matrix{}, Zp{}, false
		}
		if pivot != col {
			work.swapRows(pivot, col)
			det = Neg(det)
		}
		det = Mul(det, work.At(col, col))
		scale := Inverse(work.At(col, col))
		pivotRow := work.row(col)[col:]
		pivotRow.ScalarMul(pivotRow, &scale)
		parallelize(n, rowsPerTask, func(lo, hi int) {
			scaled := make(fr.Vector, len(pivotRow))
			for i := lo; i < hi; i++ {
				if i == col {
					continue
				}
				factor := work.At(i, col)
				row := work.row(i)[col:]
				scaled.ScalarMul(pivotRow, &factor)
				row.Sub(row, scaled)
			}
		})
	}
	inverse := NewMatrix(n, n)
	for i := range n {
		copy(inverse.row(i), work.row(i)[n:])
	}
	return inverse, det, true
}

func (m Matrix) swapRows(a, b int) {
	ra, rb := m.row(a), m.row(b)
	for j := range ra {
		ra[j], rb[j] = rb[j], ra[j]
	}
}
