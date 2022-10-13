package utilities

import (
	"fmt"
)

type Vector Matrix

func (vector Vector) assertVector() (e error) {
	if Matrix(vector).NRow() != 1 {
		e = fmt.Errorf("expects matrix of 1 by d")
	}
	return
}

func (vector Vector) assertSameLength(other Vector) (e error) {
	e = vector.assertVector()
	if e != nil {
		return
	}

	if vector.size() != other.size() {
		e = fmt.Errorf(
			"vectors lengths don't match for the operation: [1, %d] times [1, %d]",
			vector.size(), other.size(),
		)
	}
	return
}

func (vector Vector) size() int {
	return len(vector.data[0])
}

func (vector Vector) Expand(extras ...Element) (output Vector, e error) {
	e = vector.assertVector()
	if e != nil {
		return
	}
	output.data = make([][]Element, 1)
	output.data[0] = append(vector.data[0], extras...)
	return
}

func (vector Vector) Power(base Element) (output Vector, e error) {
	e = vector.assertVector()
	if e != nil {
		return
	}

	output = Vector(Matrix(vector).Power(base))

	return
}

func (pp Pairing) VectorZpFromInt(data []int32) (output Vector) {

	output = Vector(pp.MatrixZpFromInt([][]int32{data}))

	return
}

func (pp Pairing) VectorZpRandom(m int) (output Vector) {

	output = Vector(pp.MatrixZpRandom(1, m))

	return
}

func (vector Vector) Merge(other Vector) (output Vector, e error) {
	mergedMatrices, e := Matrix(vector).Merge(Matrix(other))
	if e != nil {
		return
	}
	output = Vector(mergedMatrices)

	e = output.assertVector()
	if e != nil {
		return
	}

	return
}

func (vector Vector) EqualTo(other Vector) (result bool, e error) {

	e = vector.assertVector()
	if e != nil {
		return
	}

	result = Matrix(vector).EqualTo(Matrix(other))
	return
}

func (vector Vector) InnerProduct(other Vector) (output Element, e error) {
	e = vector.assertSameLength(other)
	if e != nil {
		return
	}

	output = vector.data[0][0].Zero()
	for i := 0; i < vector.size(); i++ {
		output = output.Add(vector.data[0][i].Multiply(other.data[0][i]))
	}
	return
}

func (vector Vector) Add(other Vector) (output Vector, e error) {
	e = vector.assertSameLength(other)
	if e != nil {
		return
	}

	addedMatrices, e := Matrix(vector).Add(Matrix(other))
	if e != nil {
		return
	}
	output = Vector(addedMatrices)

	return
}

func (vector Vector) TimesMatrix(matrix Matrix) (output Vector, e error) {

	e = vector.assertVector()
	if e != nil {
		return
	}

	multipliedMatrices, e := Matrix(vector).Multiply(matrix)

	output = Vector(multipliedMatrices)

	return
}

func (pp Pairing) PairVectors(left Vector, right Vector) (output Element, e error) {

	e = left.assertSameLength(right)
	if e != nil {
		return
	}

	for i := 0; i < left.size(); i++ {
		if i == 0 {
			output = pp.Pair(left.data[0][i], right.data[0][i])
		} else {
			output = output.Add(pp.Pair(left.data[0][i], right.data[0][i]))
		}
	}

	return
}
