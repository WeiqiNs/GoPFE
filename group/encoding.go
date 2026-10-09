package group

import (
	"encoding/binary"
	"errors"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	ErrTruncated     = errors.New("group: encoding is truncated")
	ErrTrailingBytes = errors.New("group: encoding has trailing bytes")
	ErrInvalidScalar = errors.New("group: encoding holds an invalid scalar")
	ErrInvalidPoint  = errors.New("group: encoding holds an invalid point")
)

const dimensionBytes = 4

type Encoder struct {
	data []byte
}

type Decoder struct {
	data []byte
	err  error
}

type compressedPoint[P any] interface {
	*P
	SetBytes(buf []byte) (int, error)
}

func NewEncoder(n int) *Encoder {
	return &Encoder{data: binary.BigEndian.AppendUint32(nil, uint32(n))}
}

func (e *Encoder) Zp(z Zp) *Encoder {
	bytes := z.Bytes()
	e.data = append(e.data, bytes[:]...)
	return e
}

func (e *Encoder) Vector(v Vector) *Encoder {
	for _, z := range v {
		e.Zp(z)
	}
	return e
}

func (e *Encoder) Matrix(m Matrix) *Encoder {
	return e.Vector(Vector(m.data))
}

func (e *Encoder) G1(p G1) *Encoder {
	bytes := p.Bytes()
	e.data = append(e.data, bytes[:]...)
	return e
}

func (e *Encoder) G1s(ps []G1) *Encoder {
	for _, p := range ps {
		e.G1(p)
	}
	return e
}

func (e *Encoder) G2(p G2) *Encoder {
	bytes := p.Bytes()
	e.data = append(e.data, bytes[:]...)
	return e
}

func (e *Encoder) G2s(ps []G2) *Encoder {
	for _, p := range ps {
		e.G2(p)
	}
	return e
}

func (e *Encoder) Bytes() []byte {
	return e.data
}

func Decode[T any](data []byte, target *T, read func(dec *Decoder, n int) T) error {
	dec := &Decoder{data: data}
	header := dec.take(1, dimensionBytes)
	if dec.err != nil {
		return dec.err
	}
	n := int(binary.BigEndian.Uint32(header))
	if err := CheckDimension(n); err != nil {
		return err
	}
	if n > len(dec.data)/fr.Bytes {
		return fmt.Errorf("%w: dimension %d exceeds the %d bytes that follow", ErrTruncated, n, len(dec.data))
	}
	value := read(dec, n)
	if dec.err != nil {
		return dec.err
	}
	if len(dec.data) > 0 {
		return fmt.Errorf("%w: %d unread bytes", ErrTrailingBytes, len(dec.data))
	}
	*target = value
	return nil
}

func (d *Decoder) take(count, size int) []byte {
	if d.err != nil {
		return nil
	}
	if count > len(d.data)/size {
		d.truncate(count, size)
		return nil
	}
	taken := d.data[:count*size]
	d.data = d.data[count*size:]
	return taken
}

func (d *Decoder) truncate(count, size int) {
	d.err = fmt.Errorf("%w: %d values of %d bytes, %d bytes left", ErrTruncated, count, size, len(d.data))
}

func (d *Decoder) scalars(data []byte) fr.Vector {
	v := make(fr.Vector, len(data)/fr.Bytes)
	for i := range v {
		if err := v[i].SetBytesCanonical(data[i*fr.Bytes : (i+1)*fr.Bytes]); err != nil {
			d.err = fmt.Errorf("%w: scalar %d: %w", ErrInvalidScalar, i, err)
			return nil
		}
	}
	return v
}

func (d *Decoder) Zp() Zp {
	return single(d.Vector(1))
}

func (d *Decoder) Vector(count int) Vector {
	return Vector(d.scalars(d.take(count, fr.Bytes)))
}

func (d *Decoder) Matrix(rows, cols int) Matrix {
	if d.err == nil && cols > len(d.data)/fr.Bytes {
		d.truncate(cols, fr.Bytes)
	}
	return Matrix{rows: rows, cols: cols, data: d.scalars(d.take(rows, cols*fr.Bytes))}
}

func (d *Decoder) G1() G1 {
	return single(d.G1s(1))
}

func (d *Decoder) G1s(count int) []G1 {
	return decodePoints[G1](d, count, bls12381.SizeOfG1AffineCompressed)
}

func (d *Decoder) G2() G2 {
	return single(d.G2s(1))
}

func (d *Decoder) G2s(count int) []G2 {
	return decodePoints[G2](d, count, bls12381.SizeOfG2AffineCompressed)
}

func decodePoints[P any, PP compressedPoint[P]](d *Decoder, count, size int) []P {
	data := d.take(count, size)
	if d.err != nil {
		return nil
	}
	points := make([]P, count)
	errs := make([]error, count)
	parallelize(count, pointsPerTask, func(lo, hi int) {
		for i := lo; i < hi; i++ {
			_, errs[i] = PP(&points[i]).SetBytes(data[i*size : (i+1)*size])
		}
	})
	for i, err := range errs {
		if err != nil {
			d.err = fmt.Errorf("%w: point %d: %w", ErrInvalidPoint, i, err)
			return nil
		}
	}
	return points
}

func single[T any](values []T) T {
	var value T
	if len(values) == 1 {
		value = values[0]
	}
	return value
}
