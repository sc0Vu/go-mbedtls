package mbedtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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

func TestMD5HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_MD5, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(md5.New, key)

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
			t.Fatalf("hmac md5 result didn't match")
		}
		mhmac.Reset()
		ghmac.Reset()
	}
}

func TestSHA1HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA1, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(sha1.New, key)

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
			t.Fatalf("hmac sha1 result didn't match")
		}
		mhmac.Reset()
		ghmac.Reset()
	}
}

func TestSHA256HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA256, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(sha256.New, key)

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
			t.Fatalf("hmac sha256 result didn't match")
		}
		mhmac.Reset()
		ghmac.Reset()
	}
}

func TestSHA512HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA512, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(sha512.New, key)

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
			t.Fatalf("hmac sha512 result didn't match")
		}
		mhmac.Reset()
		ghmac.Reset()
	}
}

func TestRIPEMD160HMAC(t *testing.T) {
	mhmac, err := NewHMAC(MESSAGE_DIGEST_RIPEMD160, key)
	if err != nil {
		t.Fatalf("Unable to create new HMAC: %s", err)
	}
	ghmac := hmac.New(ripemd160.New, key)

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
			t.Fatalf("hmac ripemd160 result didn't match")
		}
		mhmac.Reset()
		ghmac.Reset()
	}
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

func BenchmarkMbedtlsSHA256HMAC(b *testing.B) {
	src := []byte("helloworld")
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA256, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
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

func BenchmarkCryptoSHA256HMAC(b *testing.B) {
	src := []byte("helloworld")
	ghmac := hmac.New(sha256.New, key)
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

func Benchmark1MBMbedtlsSHA256HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	mhmac, err := NewHMAC(MESSAGE_DIGEST_SHA256, key)
	if err != nil {
		b.Fatalf("unable to create new HMAC: %s", err)
	}
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

func Benchmark1MBCryptoSHA256HMAC(b *testing.B) {
	src := fakeData(1024 * 1024)
	ghmac := hmac.New(sha256.New, key)
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
