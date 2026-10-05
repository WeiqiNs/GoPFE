package group

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type DlogTable struct {
	lo    int64
	span  uint64
	steps uint64
	shift GT
	giant GT
	baby  map[[bls12381.SizeOfGT]byte]uint64
}

func babyStepCount(span uint64) uint64 {
	var root uint64
	for bit := uint64(1) << 31; bit != 0; bit >>= 1 {
		if candidate := root | bit; candidate <= span/candidate {
			root = candidate
		}
	}
	return root + 1
}

func NewDlogTable(base GT, lo, hi int64) *DlogTable {
	if lo > hi {
		panic("group: a discrete-log table needs lo <= hi")
	}
	span := uint64(hi) - uint64(lo)
	steps := babyStepCount(span)
	t := &DlogTable{
		lo:    lo,
		span:  span,
		steps: steps,
		shift: ExpGT(base, Neg(NewZp(lo))),
		giant: ExpGT(base, Neg(NewZp(int64(steps)))),
		baby:  make(map[[bls12381.SizeOfGT]byte]uint64, steps),
	}
	var power GT
	power.SetOne()
	for j := range steps {
		key := power.Bytes()
		if _, seen := t.baby[key]; !seen {
			t.baby[key] = j
		}
		power = MulGT(power, base)
	}
	return t
}

func (t *DlogTable) Find(target GT) (int64, bool) {
	gamma := MulGT(target, t.shift)
	for i := uint64(0); i <= t.span/t.steps; i++ {
		if j, ok := t.baby[gamma.Bytes()]; ok && i*t.steps+j <= t.span {
			return int64(uint64(t.lo) + i*t.steps + j), true
		}
		gamma = MulGT(gamma, t.giant)
	}
	return 0, false
}

type Decryption struct {
	Value int64
	OK    bool
}

func DecryptEach[C any](cts []C, decrypt func(C) (int64, bool)) []Decryption {
	results := make([]Decryption, len(cts))
	for i, ct := range cts {
		results[i].Value, results[i].OK = decrypt(ct)
	}
	return results
}

func Dlog(base, target GT, lo, hi int64) (int64, bool) {
	return NewDlogTable(base, lo, hi).Find(target)
}
