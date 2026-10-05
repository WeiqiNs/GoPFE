package test

import (
	"testing"

	"github.com/WeiqiNs/GoPFE/group"
	"github.com/WeiqiNs/GoPFE/ipfe/bjk"
	"github.com/WeiqiNs/GoPFE/ipfe/kim"
	"github.com/WeiqiNs/GoPFE/ipfe/kks"
	"github.com/WeiqiNs/GoPFE/ipfe/lin"
	"github.com/WeiqiNs/GoPFE/ipfe/opt"
	"github.com/WeiqiNs/GoPFE/ipfe/tao"
	"github.com/WeiqiNs/GoPFE/qfe/bcfg"
	"github.com/WeiqiNs/GoPFE/qfe/sgp"
)

type scheme interface {
	schemeName() string
	test(t *testing.T)
	benchmark(b *testing.B, n int)
}

type decryptor[K, C any] func(K, C) (int64, bool)

type innerProduct[M, K, C any] struct {
	name      string
	setup     func(int) M
	keyGen    func(M, []int64) (K, error)
	encrypt   func(M, []int64) (C, error)
	decryptor func(M, int64, int64) decryptor[K, C]
}

type quadratic[P, M, K, C any] struct {
	name      string
	setup     func(int) (P, M)
	keyGen    func(M, [][]int64) (K, error)
	encrypt   func(P, []int64, []int64) (C, error)
	decryptor func(P, int64, int64) decryptor[K, C]
}

func rangeDecryptor[M, K, C any](decrypt func(K, C, int64, int64) (int64, bool)) func(M, int64, int64) decryptor[K, C] {
	return func(_ M, lo, hi int64) decryptor[K, C] {
		return func(k K, c C) (int64, bool) { return decrypt(k, c, lo, hi) }
	}
}

func tableDecryptor[M, K, C any](
	base func(M) group.GT, decrypt func(*group.DlogTable, K, C) (int64, bool),
) func(M, int64, int64) decryptor[K, C] {
	return func(state M, lo, hi int64) decryptor[K, C] {
		table := group.NewDlogTable(base(state), lo, hi)
		return func(k K, c C) (int64, bool) { return decrypt(table, k, c) }
	}
}

func generatorBase[M any](base func() group.GT) func(M) group.GT {
	return func(M) group.GT { return base() }
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

var innerProductSchemes = []scheme{
	innerProduct[bjk.MasterKey, bjk.Key, bjk.Ciphertext]{
		name: "Bishop et al.", setup: bjk.Setup, keyGen: bjk.KeyGen, encrypt: bjk.Encrypt,
		decryptor: rangeDecryptor[bjk.MasterKey](bjk.Decrypt),
	},
	innerProduct[tao.MasterKey, tao.Key, tao.Ciphertext]{
		name: "Tomida et al.", setup: tao.Setup, keyGen: tao.KeyGen, encrypt: tao.Encrypt,
		decryptor: tableDecryptor(func(msk tao.MasterKey) group.GT { return msk.Base }, tao.Decrypt),
	},
	innerProduct[kim.MasterKey, kim.Key, kim.Ciphertext]{
		name: "Kim et al.", setup: kim.Setup, keyGen: kim.KeyGen, encrypt: kim.Encrypt,
		decryptor: rangeDecryptor[kim.MasterKey](kim.Decrypt),
	},
	innerProduct[lin.MasterKey, lin.Key, lin.Ciphertext]{
		name: "Lin", setup: lin.Setup, keyGen: lin.KeyGen, encrypt: lin.Encrypt,
		decryptor: tableDecryptor(generatorBase[lin.MasterKey](lin.Base), lin.Decrypt),
	},
	innerProduct[kks.MasterKey, kks.Key, kks.Ciphertext]{
		name: "Kim, Kim and Seo", setup: kks.Setup, keyGen: kks.KeyGen, encrypt: kks.Encrypt,
		decryptor: tableDecryptor(generatorBase[kks.MasterKey](kks.Base), kks.Decrypt),
	},
	innerProduct[opt.MasterKey, opt.Key, opt.Ciphertext]{
		name: "Ojaswi et al.", setup: opt.Setup, keyGen: opt.KeyGen, encrypt: opt.Encrypt,
		decryptor: tableDecryptor(generatorBase[opt.MasterKey](opt.Base), opt.Decrypt),
	},
}

var quadraticSchemes = []scheme{
	quadratic[bcfg.PublicKey, bcfg.MasterKey, bcfg.Key, bcfg.Ciphertext]{
		name: "Baltico et al.", setup: bcfg.Setup, keyGen: bcfg.KeyGen, encrypt: bcfg.Encrypt,
		decryptor: func(pk bcfg.PublicKey, lo, hi int64) decryptor[bcfg.Key, bcfg.Ciphertext] {
			table := group.NewDlogTable(bcfg.Base(), lo, hi)
			return func(k bcfg.Key, c bcfg.Ciphertext) (int64, bool) { return bcfg.Decrypt(table, pk, k, c) }
		},
	},
	quadratic[sgp.PublicKey, sgp.MasterKey, sgp.Key, sgp.Ciphertext]{
		name: "Dufour-Sans et al.", setup: sgp.Setup, keyGen: sgp.KeyGen, encrypt: sgp.Encrypt,
		decryptor: tableDecryptor(generatorBase[sgp.PublicKey](sgp.Base), sgp.Decrypt),
	},
}
