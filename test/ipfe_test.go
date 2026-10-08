package test

import (
	"errors"
	"testing"

	"github.com/WeiqiNs/GoPFE/group"
)

func (s innerProduct[M, K, P, C]) schemeName() string { return s.name }

func TestInnerProduct(t *testing.T) {
	for _, s := range innerProductSchemes {
		t.Run(s.schemeName(), s.test)
	}
}

func (s innerProduct[M, K, P, C]) test(t *testing.T) {
	t.Run("DecryptsInnerProductsExactlyWithinTheRange", func(t *testing.T) {
		msk := s.setup(4)
		decrypt, decryptPrepared := s.decryptors(msk, -100, 100)
		sk := must(s.keyGen(msk, []int64{1, -2, 3, 4}))
		prepared := s.prepare(sk)
		cases := []struct {
			x    []int64
			want int64
			ok   bool
		}{
			{[]int64{5, 6, 7, 8}, 46, true},
			{[]int64{-4, 5, -6, 0}, -32, true},
			{[]int64{2, 1, 0, 0}, 0, true},
			{[]int64{0, 0, 0, 25}, 100, true},
			{[]int64{0, 0, 0, -25}, -100, true},
			{[]int64{1, 0, 0, 25}, 0, false},
			{[]int64{-1, 0, 0, -25}, 0, false},
		}
		for _, c := range cases {
			ct := must(s.encrypt(msk, c.x))
			if got, ok := decrypt(sk, ct); got != c.want || ok != c.ok {
				t.Errorf("x = %v: got (%d, %v), want (%d, %v)", c.x, got, ok, c.want, c.ok)
			}
			if got, ok := decryptPrepared(prepared, ct); got != c.want || ok != c.ok {
				t.Errorf("x = %v with a prepared key: got (%d, %v), want (%d, %v)", c.x, got, ok, c.want, c.ok)
			}
		}
	})

	t.Run("DecryptsOneCiphertextUnderManyKeys", func(t *testing.T) {
		msk := s.setup(4)
		decrypt, _ := s.decryptors(msk, -100, 100)
		ct := must(s.encrypt(msk, []int64{5, 6, 7, 8}))
		cases := []struct {
			y    []int64
			want int64
		}{
			{[]int64{1, -2, 3, 4}, 46},
			{[]int64{0, 0, 0, 1}, 8},
			{[]int64{1, 1, 1, 1}, 26},
		}
		for _, c := range cases {
			if got, ok := decrypt(must(s.keyGen(msk, c.y)), ct); got != c.want || !ok {
				t.Errorf("y = %v: got (%d, %v), want (%d, true)", c.y, got, ok, c.want)
			}
		}
	})

	t.Run("HandlesVectorsOfLengthOne", func(t *testing.T) {
		msk := s.setup(1)
		decrypt, _ := s.decryptors(msk, -100, 100)
		if got, ok := decrypt(must(s.keyGen(msk, []int64{-3})), must(s.encrypt(msk, []int64{7}))); got != -21 || !ok {
			t.Errorf("got (%d, %v), want (-21, true)", got, ok)
		}
	})

	t.Run("RejectsVectorsOfTheWrongLength", func(t *testing.T) {
		msk := s.setup(4)
		for _, v := range [][]int64{{1, 2, 3}, {1, 2, 3, 4, 5}} {
			if _, err := s.keyGen(msk, v); !errors.Is(err, group.ErrShape) {
				t.Errorf("keyGen(%v): got %v, want ErrShape", v, err)
			}
			if _, err := s.encrypt(msk, v); !errors.Is(err, group.ErrShape) {
				t.Errorf("encrypt(%v): got %v, want ErrShape", v, err)
			}
		}
	})
}
