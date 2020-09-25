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

func TestMD5MD(t *testing.T) {
	var cout []byte
	var err error
	var md *MessageDigest
	var gmd hash.Hash
	gmd = md5.New()
	for _, test := range hmacTests {

		if md, err = NewMessageDigestWithContext(MESSAGE_DIGEST_MD5); err != nil {
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
			t.Fatalf("md5 hash result didn't match")
		}
		gmd.Reset()
	}
}

func TestSHA1MD(t *testing.T) {
	var cout []byte
	var err error
	var md *MessageDigest
	var gmd hash.Hash
	gmd = sha1.New()
	for _, test := range hmacTests {

		if md, err = NewMessageDigestWithContext(MESSAGE_DIGEST_SHA1); err != nil {
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
			t.Fatalf("sha1 hash result didn't match")
		}
		gmd.Reset()
	}
}

func TestSHA256MD(t *testing.T) {
	var cout []byte
	var err error
	var md *MessageDigest
	var gmd hash.Hash
	gmd = sha256.New()
	for _, test := range hmacTests {

		if md, err = NewMessageDigestWithContext(MESSAGE_DIGEST_SHA256); err != nil {
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
			t.Fatalf("sha256 hash result didn't match")
		}
		gmd.Reset()
	}
}

func TestSHA512MD(t *testing.T) {
	var cout []byte
	var err error
	var md *MessageDigest
	var gmd hash.Hash
	gmd = sha512.New()
	for _, test := range hmacTests {

		if md, err = NewMessageDigestWithContext(MESSAGE_DIGEST_SHA512); err != nil {
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
			t.Fatalf("sha512 hash result didn't match")
		}
		gmd.Reset()
	}
}

func TestRIPEMD160MD(t *testing.T) {
	var cout []byte
	var err error
	var md *MessageDigest
	var gmd hash.Hash
	gmd = ripemd160.New()
	for _, test := range hmacTests {

		if md, err = NewMessageDigestWithContext(MESSAGE_DIGEST_RIPEMD160); err != nil {
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
			t.Fatalf("ripemd160 hash result didn't match")
		}
		gmd.Reset()
	}
}

func BenchmarkMbedtlsSHA256MD(b *testing.B) {
	src := []byte("helloworld")
	md, err := NewMessageDigestWithContext(MESSAGE_DIGEST_SHA256)
	if err != nil {
		b.Fatalf("unable to create new md: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if err = md.Write(src); err != nil {
			b.Fatalf("unable to write data into md: %s", err)
		}
		if _, err = md.Finish(); err != nil {
			b.Fatalf("error while finalizing md: %s", err)
		}
	}
}

func BenchmarkCryptoSHA256MD(b *testing.B) {
	src := []byte("helloworld")
	gd := sha256.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if _, err = gd.Write(src); err != nil {
			b.Fatalf("unable to write data into md: %s", err)
		}
		_ = gd.Sum(nil)
		gd.Reset()
	}
}

func Benchmark1MBMbedtlsSHA256MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	md, err := NewMessageDigestWithContext(MESSAGE_DIGEST_SHA256)
	if err != nil {
		b.Fatalf("unable to create new md: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if err = md.Write(src); err != nil {
			b.Fatalf("unable to write data into md: %s", err)
		}
		if _, err = md.Finish(); err != nil {
			b.Fatalf("error while finalizing md: %s", err)
		}
	}
}

func Benchmark1MBCryptoSHA256MD(b *testing.B) {
	src := fakeData(1024 * 1024)
	gd := sha256.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if _, err = gd.Write(src); err != nil {
			b.Fatalf("unable to write data into md: %s", err)
		}
		_ = gd.Sum(nil)
		gd.Reset()
	}
}
