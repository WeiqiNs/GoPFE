package group

import (
	"errors"
	"fmt"
	"slices"
)

var ErrShape = errors.New("group: input has the wrong shape")

type Vector []Zp

type Matrix struct {
	rows, cols int
	data       []Zp
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
	for i := range v {
		v[i] = RandomZp()
	}
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
	r := make(Vector, len(v))
	for i := range v {
		r[i] = Add(v[i], w[i])
	}
	return r
}

func (v Vector) Scale(k Zp) Vector {
	r := make(Vector, len(v))
	for i := range v {
		r[i] = Mul(v[i], k)
	}
	return r
}

func Inner(v, w Vector) Zp {
	mustMatch(len(v), len(w))
	var total Zp
	for i := range v {
		total = Add(total, Mul(v[i], w[i]))
	}
	return total
}

func NewMatrix(rows, cols int) Matrix {
	return Matrix{rows: rows, cols: cols, data: make([]Zp, rows*cols)}
}

func RandomMatrix(rows, cols int) Matrix {
	m := NewMatrix(rows, cols)
	for i := range m.data {
		m.data[i] = RandomZp()
	}
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
		copy(m.data[i*n:], v)
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
	for i, z := range m.data {
		r.data[i] = Mul(z, k)
	}
	return r
}

func (m Matrix) MulVec(v Vector) Vector {
	mustMatch(m.cols, len(v))
	r := make(Vector, m.rows)
	for i := range r {
		r[i] = Inner(m.data[i*m.cols:(i+1)*m.cols], v)
	}
	return r
}

func (v Vector) MulMat(m Matrix) Vector {
	mustMatch(len(v), m.rows)
	r := make(Vector, m.cols)
	for i, vi := range v {
		for j := range r {
			r[j] = Add(r[j], Mul(vi, m.At(i, j)))
		}
	}
	return r
}

func (m Matrix) invert() (Matrix, Zp, bool) {
	n := m.rows
	work := NewMatrix(n, 2*n)
	for i := range n {
		copy(work.data[i*2*n:], m.data[i*n:(i+1)*n])
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
		for j := col; j < 2*n; j++ {
			work.set(col, j, Mul(work.At(col, j), scale))
		}
		for i := range n {
			factor := work.At(i, col)
			if i == col || factor.IsZero() {
				continue
			}
			for j := col; j < 2*n; j++ {
				work.set(i, j, Sub(work.At(i, j), Mul(factor, work.At(col, j))))
			}
		}
	}
	inverse := NewMatrix(n, n)
	for i := range n {
		copy(inverse.data[i*n:], work.data[i*2*n+n:(i+1)*2*n])
	}
	return inverse, det, true
}

func (m Matrix) swapRows(a, b int) {
	for j := range m.cols {
		x, y := m.At(a, j), m.At(b, j)
		m.set(a, j, y)
		m.set(b, j, x)
	}
}
