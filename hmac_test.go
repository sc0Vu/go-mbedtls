package mbedtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

type hmacTest struct {
	src []byte
}

var hmacTests = []hmacTest{
	hmacTest{
		src: []byte("hello"),
	},
	hmacTest{
		src: []byte(""),
	},
	hmacTest{
		src: []byte{0},
	},
}

var key = []byte("1234567891aabbccddee")

func doHMACTest(t *testing.T, mhmac *HMAC, ghmac hash.Hash) {
	var err error
	for _, test := range hmacTests {
		var cout []byte
		if err := mhmac.Write(test.src); err != nil {
			t.Fatalf("unable to write data into HMAC: %s", err)
		}
		if cout, err = mhmac.Finish(); err != nil {
			t.Fatalf("error while finalizing HMAC: %s", err)
		}
		ghmac.Write(test.src)
		mout := ghmac.Sum(nil)
		if !bytes.Equal(cout, mout) {
			t.Fatalf("hmac result didn't match")
		}
		mhmac.Reset()
		ghmac.Reset()
	}
}

func TestMD5HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_MD5, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(md5.New, key)
	doHMACTest(t, mhmac, ghmac)
}

func TestSHA1HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA1, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(sha1.New, key)
	doHMACTest(t, mhmac, ghmac)
}

func TestSHA256HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA256, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(sha256.New, key)
	doHMACTest(t, mhmac, ghmac)
}

func TestSHA512HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA512, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(sha512.New, key)
	doHMACTest(t, mhmac, ghmac)
}

func TestRIPEMD160HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_RIPEMD160, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(ripemd160.New, key)
	doHMACTest(t, mhmac, ghmac)
}

func fakeData(size int) (data []byte) {
	// if size > math.MaxUint32 {
	// 	size = math.MaxUint32
	// }
	data = make([]byte, size)
	for i := 0; i < size; i++ {
		data[i] = byte(i)
	}
	return
}

func doMbedtlsHMACBench(b *testing.B, mhmac *HMAC, src []byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if err = mhmac.Write(src); err != nil {
			b.Fatalf("unable to write data into HMAC: %s", err)
		}
		if _, err = mhmac.Finish(); err != nil {
			b.Fatalf("error while finalizing HMAC: %s", err)
		}
		mhmac.Reset()
	}
}

func doCryptoHMACBench(b *testing.B, ghmac hash.Hash, src []byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if _, err = ghmac.Write(src); err != nil {
			b.Fatalf("unable to write data into HMAC: %s", err)
		}
		ghmac.Sum(nil)
		ghmac.Reset()
	}
}

// MD5
func BenchmarkMbedtlsMD5HMAC(b *testing.B) {
	src := []byte("helloworld")
	mhmac, err := NewHMAC(MESSAGE_DIGEST_MD5, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func BenchmarkCryptoMD5HMAC(b *testing.B) {
	src := []byte("helloworld")
	ghmac := hmac.New(md5.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

func Benchmark1MBMbedtlsMD5HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	mhmac, err := NewHMAC(MESSAGE_DIGEST_MD5, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func Benchmark1MBCryptoMD5HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	ghmac := hmac.New(md5.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

// sha1
func BenchmarkMbedtlsSHA1HMAC(b *testing.B) {
	src := []byte("helloworld")
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA1, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func BenchmarkCryptoSHA1HMAC(b *testing.B) {
	src := []byte("helloworld")
	ghmac := hmac.New(sha1.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

func Benchmark1MBMbedtlsSHA1HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA1, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func Benchmark1MBCryptoSHA1HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	ghmac := hmac.New(sha1.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

// sha256
func BenchmarkMbedtlsSHA256HMAC(b *testing.B) {
	src := []byte("helloworld")
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA256, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func BenchmarkCryptoSHA256HMAC(b *testing.B) {
	src := []byte("helloworld")
	ghmac := hmac.New(sha256.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

func Benchmark1MBMbedtlsSHA256HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA256, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func Benchmark1MBCryptoSHA256HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	ghmac := hmac.New(sha256.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

// sha512
func BenchmarkMbedtlsSHA512HMAC(b *testing.B) {
	src := []byte("helloworld")
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA512, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func BenchmarkCryptoSHA512HMAC(b *testing.B) {
	src := []byte("helloworld")
	ghmac := hmac.New(sha512.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

func Benchmark1MBMbedtlsSHA512HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA512, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func Benchmark1MBCryptoSHA512HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	ghmac := hmac.New(sha512.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

// ripemd160
func BenchmarkMbedtlsRIPEMD160HMAC(b *testing.B) {
	src := []byte("helloworld")
	mhmac, err := NewHMAC(MESSAGE_DIGEST_RIPEMD160, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func BenchmarkCryptoRIPEMD160HMAC(b *testing.B) {
	src := []byte("helloworld")
	ghmac := hmac.New(ripemd160.New, key)
	doCryptoHMACBench(b, ghmac, src)
}

func Benchmark1MBMbedtlsRIPEMD160HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	mhmac, err := NewHMAC(MESSAGE_DIGEST_RIPEMD160, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
	doMbedtlsHMACBench(b, mhmac, src)
}

func Benchmark1MBCryptoRIPEMD160HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	ghmac := hmac.New(ripemd160.New, key)
	doCryptoHMACBench(b, ghmac, src)
}
