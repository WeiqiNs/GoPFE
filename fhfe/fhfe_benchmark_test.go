package fhfe

import (
	"fmt"
	"testing"
)

func BenchmarkFHFESetup(b *testing.B) {
	for _, n := range []int{100, 200, 250, 300} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _, _, _, _, _ = Setup(n)
			}
		})
	}
}

func BenchmarkFHFEEncrypt(b *testing.B) {
	for _, n := range []int{100, 200, 250, 300} {
		B, _, pp, _, g, _, _ := Setup(n)
		x := pp.VectorZpRandom(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = Encrypt(B, x, pp, g)
			}
		})
	}
}

func BenchmarkFHFEKeyGen(b *testing.B) {
	for _, n := range []int{100, 200, 250, 300} {
		_, BStar, pp, _, g, _, _ := Setup(n)
		x := pp.VectorZpRandom(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = KeyGen(BStar, x, pp, g)
			}
		})
	}
}
