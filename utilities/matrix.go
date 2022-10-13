package utilities

import (
	"fmt"
	"strings"
)

type Matrix struct {
	data [][]Element
}

func (matrix Matrix) NRow() int {
	return len(matrix.data)
}

func (matrix Matrix) NCol() int {
	if matrix.NRow() == 0 {
		return 0
	}
	return len(matrix.data[0])
}

func (matrix Matrix) String() string {
	var sb strings.Builder

	if matrix.NCol() == 0 || matrix.NRow() == 0 {
		return "Matrix empty"
	}

	_, err := fmt.Fprintf(&sb, "\nMatrix %d by %d\n", matrix.NRow(), matrix.NCol())
	if err != nil {
		return ""
	}

	sb.WriteString("[\n")
	for i := 0; i < matrix.NRow(); i++ {
		sb.WriteString("\t[")
		for j := 0; j < matrix.NCol(); j++ {
			sb.WriteString(matrix.data[i][j].String())
			if j != matrix.NCol()-1 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("]\n")
	}
	sb.WriteString("]\n")

	return sb.String()
}

func (pp Pairing) MatrixZpFromInt(data [][]int32) (output Matrix) {
	output.data = make([][]Element, len(data))

	for i := range output.data {
		output.data[i] = make([]Element, len(data[i]))
		for j, ele := range data[i] {
			output.data[i][j] = pp.ZpFromInt(ele)
		}
	}

	return
}

func (pp Pairing) MatrixZpRandom(m int, n int) (output Matrix) {
	output.data = make([][]Element, m)
	for i := 0; i < m; i++ {
		output.data[i] = make([]Element, n)
	}

	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			output.data[i][j] = pp.RandomZp()
		}
	}
	return
}

func (matrix Matrix) EqualTo(right Matrix) bool {
	if matrix.NCol() != right.NCol() || matrix.NRow() != right.NRow() {
		return false
	}

	for i := 0; i < matrix.NRow(); i++ {
		for j := 0; j < matrix.NCol(); j++ {
			if !matrix.data[i][j].EqualTo(right.data[i][j]) {
				return false
			}
		}
	}

	return true
}

func (matrix Matrix) Transpose() (output Matrix) {
	output.data = make([][]Element, matrix.NCol())

	for i := 0; i < matrix.NCol(); i++ {

		output.data[i] = make([]Element, matrix.NRow())
		for j := 0; j < matrix.NRow(); j++ {
			output.data[i][j] = matrix.data[j][i].Copy()
		}
	}

	return
}

func (matrix Matrix) TimesConstant(constant Element) (output Matrix) {
	output.data = make([][]Element, matrix.NRow())
	for i := 0; i < matrix.NRow(); i++ {
		output.data[i] = make([]Element, matrix.NCol())
		for j := 0; j < matrix.NCol(); j++ {
			output.data[i][j] = matrix.data[i][j].Multiply(constant)
		}
	}
	return
}

func (matrix Matrix) Power(base Element) (output Matrix) {
	output.data = make([][]Element, matrix.NRow())
	for i := 0; i < matrix.NRow(); i++ {
		output.data[i] = make([]Element, matrix.NCol())
		for j := 0; j < matrix.NCol(); j++ {
			output.data[i][j] = base.Power(matrix.data[i][j])
		}
	}
	return
}

func (matrix Matrix) Add(right Matrix) (output Matrix, e error) {
	if matrix.NCol() != right.NCol() || matrix.NRow() != right.NRow() {
		e = fmt.Errorf(
			"matrices dimensions don't match for addition: [%d, %d] times [%d, %d]",
			matrix.NCol(), matrix.NRow(), right.NCol(), right.NRow(),
		)
		return
	}

	output.data = make([][]Element, matrix.NRow())
	for i := 0; i < matrix.NRow(); i++ {

		output.data[i] = make([]Element, right.NCol())
		for j := 0; j < right.NCol(); j++ {
			output.data[i][j] = matrix.data[i][j].Add(right.data[i][j])
		}
	}
	return
}

func (matrix Matrix) Multiply(right Matrix) (output Matrix, e error) {
	if matrix.NCol() != right.NRow() {
		e = fmt.Errorf(
			"matrices dimensions don't match for multiplication: [%d, %d] times [%d, %d]",
			matrix.NCol(), matrix.NRow(), right.NCol(), right.NRow(),
		)
		return
	}

	zero := matrix.data[0][0].Zero()
	output.data = make([][]Element, matrix.NRow())

	for i := 0; i < matrix.NRow(); i++ {
		output.data[i] = make([]Element, right.NCol())
		for j := 0; j < right.NCol(); j++ {
			output.data[i][j] = zero
			for k := 0; k < matrix.NCol(); k++ {
				output.data[i][j] = output.data[i][j].Add(matrix.data[i][k].Multiply(right.data[k][j]))
			}
		}
	}

	return
}

func (matrix Matrix) IsIdentity() bool {
	if matrix.NCol() != matrix.NRow() {
		return false
	}

	for i := 0; i < matrix.NRow(); i++ {
		for j := 0; j < matrix.NCol(); j++ {
			if i != j && !matrix.data[i][j].IsZero() {
				return false
			}
			if i == j && !matrix.data[i][j].IsOne() {
				return false
			}
		}
	}

	return true
}

func (matrix Matrix) Merge(right Matrix) (output Matrix, e error) {
	if matrix.NRow() == 0 || right.NRow() == 0 {
		e = fmt.Errorf(
			"matrices dimensions don't match for merge: [%d, %d] times [%d, %d]",
			matrix.NCol(), matrix.NRow(), right.NCol(), right.NRow(),
		)
		return
	}

	output.data = make([][]Element, matrix.NRow())
	for i := 0; i < matrix.NRow(); i++ {
		output.data[i] = append(matrix.data[i], right.data[i]...)
	}
	return
}

func (matrix Matrix) Inverse() (output Matrix, e error) {
	if matrix.NCol() != matrix.NRow() {
		e = fmt.Errorf(
			"non-square matrices are not invertible, given: [%d, %d]",
			matrix.NRow(), matrix.NCol(),
		)
		return
	}

	rowEchelon, e := matrix.Merge(MatrixIdentity(matrix.NCol(), matrix.data[0][0]))
	if e != nil {
		return
	}

	// Bottom left half to all zeros.
	for i := 0; i < rowEchelon.NRow(); i++ {
		for j := i; j < rowEchelon.NRow(); j++ {
			if i == j && !rowEchelon.data[i][j].Is1() {
				multiplier := rowEchelon.data[i][i].Inverse()
				for k := i; k < rowEchelon.NCol(); k++ {
					rowEchelon.data[j][k] = rowEchelon.data[j][k].Multiply(multiplier)
				}

			}

			if i == j && rowEchelon.data[i][j].Is0() {
				e = fmt.Errorf("the matrix is not invertible")
				return
			}

			if i != j {
				multiplier := rowEchelon.data[j][i]
				for k := i; k < rowEchelon.NCol(); k++ {
					rowEchelon.data[j][k] = rowEchelon.data[j][k].Add(rowEchelon.data[i][k].Multiply(multiplier).Negate())
				}
			}
		}
	}

	// Top right half to all zeros.
	for i := rowEchelon.NRow() - 1; i > 0; i-- {
		for j := i - 1; j >= 0; j-- {
			multiplier := rowEchelon.data[j][i]
			for k := i; k < rowEchelon.NCol(); k++ {
				rowEchelon.data[j][k] = rowEchelon.data[j][k].Add(rowEchelon.data[i][k].Multiply(multiplier).Negate())
			}
		}
	}

	output.data = make([][]Element, matrix.NRow())
	for i := 0; i < matrix.NRow(); i++ {
		output.data[i] = make([]Element, matrix.NRow())
		for j := 0; j < matrix.NRow(); j++ {
			output.data[i][j] = rowEchelon.data[i][j+matrix.NRow()].Copy()
		}
	}

	return
}

func MatrixIdentity(n int, from Element) (output Matrix) {
	output.data = make([][]Element, n)
	for i := 0; i < n; i++ {
		output.data[i] = make([]Element, n)
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				output.data[i][j] = from.One()
			} else {
				output.data[i][j] = from.Zero()
			}
		}
	}
	return
}
