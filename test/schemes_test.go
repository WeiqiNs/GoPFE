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

type batchDecryptor[K, C any] func(K, []C) []group.Decryption

type decryptors[S, K, C any] func(S, int64, int64) (decryptor[K, C], batchDecryptor[K, C])

type innerProduct[M, K, C any] struct {
	name       string
	setup      func(int) M
	keyGen     func(M, []int64) (K, error)
	encrypt    func(M, []int64) (C, error)
	decryptors decryptors[M, K, C]
}

type quadratic[P, M, K, C any] struct {
	name       string
	setup      func(int) (P, M)
	keyGen     func(M, [][]int64) (K, error)
	encrypt    func(P, []int64, []int64) (C, error)
	decryptors decryptors[P, K, C]
}

func rangeDecryptors[M, K, C any](
	decrypt func(K, C, int64, int64) (int64, bool), decryptMany func(K, []C, int64, int64) []group.Decryption,
) decryptors[M, K, C] {
	return func(_ M, lo, hi int64) (decryptor[K, C], batchDecryptor[K, C]) {
		return func(k K, c C) (int64, bool) { return decrypt(k, c, lo, hi) },
			func(k K, cs []C) []group.Decryption { return decryptMany(k, cs, lo, hi) }
	}
}

func tableDecryptors[S, K, C any](
	base func(S) group.GT,
	decrypt func(*group.DlogTable, K, C) (int64, bool),
	decryptMany func(*group.DlogTable, K, []C) []group.Decryption,
) decryptors[S, K, C] {
	return func(state S, lo, hi int64) (decryptor[K, C], batchDecryptor[K, C]) {
		table := group.NewDlogTable(base(state), lo, hi)
		return func(k K, c C) (int64, bool) { return decrypt(table, k, c) },
			func(k K, cs []C) []group.Decryption { return decryptMany(table, k, cs) }
	}
}

func generatorBase[S any](base func() group.GT) func(S) group.GT {
	return func(S) group.GT { return base() }
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
		decryptors: rangeDecryptors[bjk.MasterKey](bjk.Decrypt, bjk.DecryptMany),
	},
	innerProduct[tao.MasterKey, tao.Key, tao.Ciphertext]{
		name: "Tomida et al.", setup: tao.Setup, keyGen: tao.KeyGen, encrypt: tao.Encrypt,
		decryptors: tableDecryptors(func(msk tao.MasterKey) group.GT { return msk.Base }, tao.Decrypt, tao.DecryptMany),
	},
	innerProduct[kim.MasterKey, kim.Key, kim.Ciphertext]{
		name: "Kim et al.", setup: kim.Setup, keyGen: kim.KeyGen, encrypt: kim.Encrypt,
		decryptors: rangeDecryptors[kim.MasterKey](kim.Decrypt, kim.DecryptMany),
	},
	innerProduct[lin.MasterKey, lin.Key, lin.Ciphertext]{
		name: "Lin", setup: lin.Setup, keyGen: lin.KeyGen, encrypt: lin.Encrypt,
		decryptors: tableDecryptors(generatorBase[lin.MasterKey](lin.Base), lin.Decrypt, lin.DecryptMany),
	},
	innerProduct[kks.MasterKey, kks.Key, kks.Ciphertext]{
		name: "Kim, Kim and Seo", setup: kks.Setup, keyGen: kks.KeyGen, encrypt: kks.Encrypt,
		decryptors: tableDecryptors(generatorBase[kks.MasterKey](kks.Base), kks.Decrypt, kks.DecryptMany),
	},
	innerProduct[opt.MasterKey, opt.Key, opt.Ciphertext]{
		name: "Ojaswi et al.", setup: opt.Setup, keyGen: opt.KeyGen, encrypt: opt.Encrypt,
		decryptors: tableDecryptors(generatorBase[opt.MasterKey](opt.Base), opt.Decrypt, opt.DecryptMany),
	},
}

var quadraticSchemes = []scheme{
	quadratic[bcfg.PublicKey, bcfg.MasterKey, bcfg.Key, bcfg.Ciphertext]{
		name: "Baltico et al.", setup: bcfg.Setup, keyGen: bcfg.KeyGen, encrypt: bcfg.Encrypt,
		decryptors: tableDecryptors(generatorBase[bcfg.PublicKey](bcfg.Base), bcfg.Decrypt, bcfg.DecryptMany),
	},
	quadratic[sgp.PublicKey, sgp.MasterKey, sgp.Key, sgp.Ciphertext]{
		name: "Dufour-Sans et al.", setup: sgp.Setup, keyGen: sgp.KeyGen, encrypt: sgp.Encrypt,
		decryptors: tableDecryptors(generatorBase[sgp.PublicKey](sgp.Base), sgp.Decrypt, sgp.DecryptMany),
	},
}
