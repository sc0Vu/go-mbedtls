package mbedtls

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

type mdTest struct {
	src []byte
}

var mdTests = []mdTest{
	mdTest{
		src: []byte("hello"),
	},
	mdTest{
		src: []byte(""),
	},
	mdTest{
		src: []byte{0},
	},
}

func doMDTest(t *testing.T, newMD func() (md *MessageDigest, err error), gmd hash.Hash) {
	for _, test := range mdTests {
		var cout []byte
		var err error
		var md *MessageDigest
		if md, err = newMD(); err != nil {
			t.Fatalf("Unable to create new MD: %s", err)
		}
		if err = md.Write(test.src); err != nil {
			t.Fatalf("unable to write data into MD: %s", err)
		}
		if cout, err = md.Finish(); err != nil {
			t.Fatalf("error while finalizing MD: %s", err)
		}
		gmd.Write(test.src)
		mout := gmd.Sum(nil)
		if !bytes.Equal(cout, mout) {
			t.Fatalf("hash result didn't match %v", test.src)
		}
		// TODO: make reset works for md context
		// md.Reset()
		md.Close()
		gmd.Reset()
	}
}

func TestMD5MD(t *testing.T) {
	var gmd hash.Hash
	gmd = md5.New()

	doMDTest(t, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_MD5) }, gmd)
}

func TestSHA1MD(t *testing.T) {
	var gmd hash.Hash
	gmd = sha1.New()
	doMDTest(t, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA1) }, gmd)
}

func TestSHA256MD(t *testing.T) {
	var gmd hash.Hash
	gmd = sha256.New()
	doMDTest(t, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA256) }, gmd)
}

func TestSHA512MD(t *testing.T) {
	var gmd hash.Hash
	gmd = sha512.New()
	doMDTest(t, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA512) }, gmd)
}

func TestRIPEMD160MD(t *testing.T) {
	var gmd hash.Hash
	gmd = ripemd160.New()
	doMDTest(t, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_RIPEMD160) }, gmd)
}

func doMbedtlsMDBench(b *testing.B, newMD func() (md *MessageDigest, err error), src []byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		var md *MessageDigest
		if md, err = newMD(); err != nil {
			b.Fatalf("Unable to create new MD: %s", err)
		}
		if err = md.Write(src); err != nil {
			b.Fatalf("unable to write data into md: %s", err)
		}
		if _, err = md.Finish(); err != nil {
			b.Fatalf("error while finalizing md: %s", err)
		}
		md.Close()
	}
}

func doCryptoMDBench(b *testing.B, gmd hash.Hash, src []byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if _, err = gmd.Write(src); err != nil {
			b.Fatalf("unable to write data into md: %s", err)
		}
		_ = gmd.Sum(nil)
		gmd.Reset()
	}
}

// MD5
func BenchmarkMbedtlsMD5MD(b *testing.B) {
	src := []byte("helloworld")
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_MD5) }, src)
}

func BenchmarkCryptoMD5MD(b *testing.B) {
	src := []byte("helloworld")
	gmd := md5.New()
	doCryptoMDBench(b, gmd, src)
}

func Benchmark1MBMbedtlsMD5MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_MD5) }, src)
}

func Benchmark1MBCryptoMD5MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	gmd := md5.New()
	doCryptoMDBench(b, gmd, src)
}

// SHA1
func BenchmarkMbedtlsSHA1MD(b *testing.B) {
	src := []byte("helloworld")
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA1) }, src)
}

func BenchmarkCryptoSHA1MD(b *testing.B) {
	src := []byte("helloworld")
	gmd := sha1.New()
	doCryptoMDBench(b, gmd, src)
}

func Benchmark1MBMbedtlsSHA1MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA1) }, src)
}

func Benchmark1MBCryptoSHA1MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	gmd := sha1.New()
	doCryptoMDBench(b, gmd, src)
}

// sha256
func BenchmarkMbedtlsSHA256MD(b *testing.B) {
	src := []byte("helloworld")
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA256) }, src)
}

func BenchmarkCryptoSHA256MD(b *testing.B) {
	src := []byte("helloworld")
	gmd := sha256.New()
	doCryptoMDBench(b, gmd, src)
}

func Benchmark1MBMbedtlsSHA256MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA256) }, src)
}

func Benchmark1MBCryptoSHA256MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	gmd := sha256.New()
	doCryptoMDBench(b, gmd, src)
}

// SHA512
func BenchmarkMbedtlsSHA512MD(b *testing.B) {
	src := []byte("helloworld")
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA512) }, src)
}

func BenchmarkCryptoSHA512MD(b *testing.B) {
	src := []byte("helloworld")
	gmd := sha512.New()
	doCryptoMDBench(b, gmd, src)
}

func Benchmark1MBMbedtlsSHA512MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_SHA512) }, src)
}

func Benchmark1MBCryptoSHA512MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	gmd := sha512.New()
	doCryptoMDBench(b, gmd, src)
}

// RIPEMD160
func BenchmarkMbedtlsRIPEMD160MD(b *testing.B) {
	src := []byte("helloworld")
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_RIPEMD160) }, src)
}

func BenchmarkCryptoRIPEMD160MD(b *testing.B) {
	src := []byte("helloworld")
	gmd := ripemd160.New()
	doCryptoMDBench(b, gmd, src)
}

func Benchmark1MBMbedtlsRIPEMD160MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	doMbedtlsMDBench(b, func() (md *MessageDigest, err error) { return NewMessageDigestWithContext(MESSAGE_DIGEST_RIPEMD160) }, src)
}

func Benchmark1MBCryptoRIPEMD160MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	gmd := ripemd160.New()
	doCryptoMDBench(b, gmd, src)
}
