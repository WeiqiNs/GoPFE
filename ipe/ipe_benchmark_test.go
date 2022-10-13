package ipe

import (
	"fmt"
	"testing"
)

func BenchmarkIPESetup(b *testing.B) {
	for _, n := range []int{100, 200, 300, 400, 500, 600, 700, 768, 800, 900, 1000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _, _, _, _, _, _ = Setup(n)
			}
		})
	}
}

func BenchmarkIPEEncrypt(b *testing.B) {
	for _, n := range []int{100, 200, 300, 400, 500, 600, 700, 768, 800, 900, 1000} {
		A, B, BStar, pp, _, g, _, _ := Setup(n)
		x := pp.VectorZpRandom(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _, _ = Encrypt(x, A, B, BStar, pp, g)
			}
		})
	}
}
