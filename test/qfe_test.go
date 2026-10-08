package test

import (
	"errors"
	"testing"

	"github.com/WeiqiNs/GoPFE/group"
)

func (s quadratic[PK, M, K, P, C]) schemeName() string { return s.name }

func TestQuadratic(t *testing.T) {
	for _, s := range quadraticSchemes {
		t.Run(s.schemeName(), s.test)
	}
}

func (s quadratic[PK, M, K, P, C]) test(t *testing.T) {
	f := [][]int64{{1, 0, 2}, {0, -1, 0}, {3, 1, 1}}

	t.Run("DecryptsQuadraticFormsExactlyWithinTheRange", func(t *testing.T) {
		pk, msk := s.setup(3)
		decrypt, decryptPrepared := s.decryptors(pk, -100, 100)
		sk := must(s.keyGen(msk, f))
		prepared := s.prepare(sk)
		cases := []struct {
			x, y []int64
			want int64
			ok   bool
		}{
			{[]int64{1, -2, 3}, []int64{4, 5, -6}, 35, true},
			{[]int64{-1, 1, 0}, []int64{2, 0, 1}, -4, true},
			{[]int64{0, 0, 0}, []int64{4, 5, -6}, 0, true},
			{[]int64{1, 0, 0}, []int64{100, 0, 0}, 100, true},
			{[]int64{0, 1, 0}, []int64{0, 100, 0}, -100, true},
			{[]int64{1, 0, 0}, []int64{101, 0, 0}, 0, false},
			{[]int64{0, 1, 0}, []int64{0, 101, 0}, 0, false},
		}
		for _, c := range cases {
			ct := must(s.encrypt(pk, c.x, c.y))
			if got, ok := decrypt(sk, ct); got != c.want || ok != c.ok {
				t.Errorf("x = %v, y = %v: got (%d, %v), want (%d, %v)", c.x, c.y, got, ok, c.want, c.ok)
			}
			if got, ok := decryptPrepared(prepared, ct); got != c.want || ok != c.ok {
				t.Errorf("x = %v, y = %v with a prepared key: got (%d, %v), want (%d, %v)", c.x, c.y, got, ok, c.want, c.ok)
			}
		}
	})

	t.Run("DecryptsOneCiphertextUnderManyKeys", func(t *testing.T) {
		pk, msk := s.setup(3)
		decrypt, _ := s.decryptors(pk, -100, 100)
		ct := must(s.encrypt(pk, []int64{1, -2, 3}, []int64{4, 5, -6}))
		cases := []struct {
			f    [][]int64
			want int64
		}{
			{f, 35},
			{[][]int64{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}}, -24},
			{[][]int64{{0, 0, 0}, {0, 0, 0}, {0, 0, 1}}, -18},
		}
		for _, c := range cases {
			if got, ok := decrypt(must(s.keyGen(msk, c.f)), ct); got != c.want || !ok {
				t.Errorf("f = %v: got (%d, %v), want (%d, true)", c.f, got, ok, c.want)
			}
		}
	})

	t.Run("HandlesVectorsOfLengthOne", func(t *testing.T) {
		pk, msk := s.setup(1)
		decrypt, _ := s.decryptors(pk, -100, 100)
		ct := must(s.encrypt(pk, []int64{7}, []int64{2}))
		if got, ok := decrypt(must(s.keyGen(msk, [][]int64{{-3}})), ct); got != -42 || !ok {
			t.Errorf("got (%d, %v), want (-42, true)", got, ok)
		}
	})

	t.Run("RejectsInputsOfTheWrongShape", func(t *testing.T) {
		pk, msk := s.setup(3)
		for _, f := range [][][]int64{{{1, 2}, {3, 4}, {5, 6}}, {{1, 2}, {3, 4}}} {
			if _, err := s.keyGen(msk, f); !errors.Is(err, group.ErrShape) {
				t.Errorf("keyGen(%v): got %v, want ErrShape", f, err)
			}
		}
		for _, xy := range [][2][]int64{{{1, 2}, {1, 2, 3}}, {{1, 2, 3}, {1, 2, 3, 4}}} {
			if _, err := s.encrypt(pk, xy[0], xy[1]); !errors.Is(err, group.ErrShape) {
				t.Errorf("encrypt(%v, %v): got %v, want ErrShape", xy[0], xy[1], err)
			}
		}
	})
}
