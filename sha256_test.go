package mbedtls

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

type sha256Test struct {
	src []byte
}

var sha256Tests = []sha256Test{
	sha256Test{
		src: []byte("hello"),
	},
	sha256Test{
		src: []byte(""),
	},
	sha256Test{
		src: []byte{0},
	},
}

func TestSHA256(t *testing.T) {
	for _, test := range sha256Tests {
		cout := sha256.Sum256(test.src)
		mout, err := Sha256(test.src)
		if err != nil {
			t.Fatal(err)
		}
		if len(cout) != len(mout) {
			t.Fatalf("sha256 hash result didn't match")
		}
		if !bytes.Equal(cout[:], mout[:]) {
			t.Fatalf("sha256 hash result didn't match")
		}
	}
}

func BenchmarkSHA256(b *testing.B) {
	src := []byte("helloworld")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Sha256(src)
	}
}
