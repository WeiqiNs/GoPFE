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

type decryptors[S, K, P, C any] func(S, int64, int64) (decryptor[K, C], decryptor[P, C])

type innerProduct[M, K, P, C any] struct {
	name       string
	setup      func(int) M
	keyGen     func(M, []int64) (K, error)
	encrypt    func(M, []int64) (C, error)
	prepare    func(K) P
	decryptors decryptors[M, K, P, C]
}

type quadratic[PK, M, K, P, C any] struct {
	name       string
	setup      func(int) (PK, M)
	keyGen     func(M, [][]int64) (K, error)
	encrypt    func(PK, []int64, []int64) (C, error)
	prepare    func(K) P
	decryptors decryptors[PK, K, P, C]
}

func rangeDecryptors[M, K, P, C any](
	decrypt func(K, C, int64, int64) (int64, bool), decryptPrepared func(P, C, int64, int64) (int64, bool),
) decryptors[M, K, P, C] {
	return func(_ M, lo, hi int64) (decryptor[K, C], decryptor[P, C]) {
		return func(k K, c C) (int64, bool) { return decrypt(k, c, lo, hi) },
			func(p P, c C) (int64, bool) { return decryptPrepared(p, c, lo, hi) }
	}
}

func tableDecryptors[S, K, P, C any](
	base func(S) group.GT,
	decrypt func(*group.DlogTable, K, C) (int64, bool),
	decryptPrepared func(*group.DlogTable, P, C) (int64, bool),
) decryptors[S, K, P, C] {
	return func(state S, lo, hi int64) (decryptor[K, C], decryptor[P, C]) {
		table := group.NewDlogTable(base(state), lo, hi)
		return func(k K, c C) (int64, bool) { return decrypt(table, k, c) },
			func(p P, c C) (int64, bool) { return decryptPrepared(table, p, c) }
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
	innerProduct[bjk.MasterKey, bjk.Key, bjk.PreparedKey, bjk.Ciphertext]{
		name: "Bishop et al.", setup: bjk.Setup, keyGen: bjk.KeyGen, encrypt: bjk.Encrypt, prepare: bjk.Prepare,
		decryptors: rangeDecryptors[bjk.MasterKey](bjk.Decrypt[bjk.Key], bjk.Decrypt[bjk.PreparedKey]),
	},
	innerProduct[tao.MasterKey, tao.Key, tao.PreparedKey, tao.Ciphertext]{
		name: "Tomida et al.", setup: tao.Setup, keyGen: tao.KeyGen, encrypt: tao.Encrypt, prepare: tao.Prepare,
		decryptors: tableDecryptors(
			func(msk tao.MasterKey) group.GT { return msk.Base }, tao.Decrypt[tao.Key], tao.Decrypt[tao.PreparedKey],
		),
	},
	innerProduct[kim.MasterKey, kim.Key, kim.PreparedKey, kim.Ciphertext]{
		name: "Kim et al.", setup: kim.Setup, keyGen: kim.KeyGen, encrypt: kim.Encrypt, prepare: kim.Prepare,
		decryptors: rangeDecryptors[kim.MasterKey](kim.Decrypt[kim.Key], kim.Decrypt[kim.PreparedKey]),
	},
	innerProduct[lin.MasterKey, lin.Key, lin.PreparedKey, lin.Ciphertext]{
		name: "Lin", setup: lin.Setup, keyGen: lin.KeyGen, encrypt: lin.Encrypt, prepare: lin.Prepare,
		decryptors: tableDecryptors(
			generatorBase[lin.MasterKey](lin.Base), lin.Decrypt[lin.Key], lin.Decrypt[lin.PreparedKey],
		),
	},
	innerProduct[kks.MasterKey, kks.Key, kks.PreparedKey, kks.Ciphertext]{
		name: "Kim, Kim and Seo", setup: kks.Setup, keyGen: kks.KeyGen, encrypt: kks.Encrypt, prepare: kks.Prepare,
		decryptors: tableDecryptors(
			generatorBase[kks.MasterKey](kks.Base), kks.Decrypt[kks.Key], kks.Decrypt[kks.PreparedKey],
		),
	},
	innerProduct[opt.MasterKey, opt.Key, opt.PreparedKey, opt.Ciphertext]{
		name: "Ojaswi et al.", setup: opt.Setup, keyGen: opt.KeyGen, encrypt: opt.Encrypt, prepare: opt.Prepare,
		decryptors: tableDecryptors(
			generatorBase[opt.MasterKey](opt.Base), opt.Decrypt[opt.Key], opt.Decrypt[opt.PreparedKey],
		),
	},
}

var quadraticSchemes = []scheme{
	quadratic[bcfg.PublicKey, bcfg.MasterKey, bcfg.Key, bcfg.PreparedKey, bcfg.Ciphertext]{
		name: "Baltico et al.", setup: bcfg.Setup, keyGen: bcfg.KeyGen, encrypt: bcfg.Encrypt, prepare: bcfg.Prepare,
		decryptors: tableDecryptors(
			generatorBase[bcfg.PublicKey](bcfg.Base), bcfg.Decrypt[bcfg.Key], bcfg.Decrypt[bcfg.PreparedKey],
		),
	},
	quadratic[sgp.PublicKey, sgp.MasterKey, sgp.Key, sgp.PreparedKey, sgp.Ciphertext]{
		name: "Dufour-Sans et al.", setup: sgp.Setup, keyGen: sgp.KeyGen, encrypt: sgp.Encrypt, prepare: sgp.Prepare,
		decryptors: tableDecryptors(
			generatorBase[sgp.PublicKey](sgp.Base), sgp.Decrypt[sgp.Key], sgp.Decrypt[sgp.PreparedKey],
		),
	},
}
