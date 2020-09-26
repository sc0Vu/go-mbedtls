package mbedtls

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

type sha1Test struct {
	src []byte
}

var sha1Tests = []sha1Test{
	sha1Test{
		src: []byte("hello"),
	},
	sha1Test{
		src: []byte(""),
	},
	sha1Test{
		src: []byte{0},
	},
}

func TestSHA1(t *testing.T) {
	for _, test := range sha1Tests {
		cout := sha1.Sum(test.src)
		mout, err := Sha1(test.src)
		if err != nil {
			t.Fatal(err)
		}
		if len(cout) != len(mout) {
			t.Fatalf("sha1 hash result didn't match")
		}
		if !bytes.Equal(cout[:], mout[:]) {
			t.Fatalf("sha1 hash result didn't match")
		}
	}
}

// func BenchmarkSHA1(b *testing.B) {
// 	src := []byte("helloworld")
// 	b.ResetTimer()
// 	for n := 0; n < b.N; n++ {
// 		Sha1(src)
// 	}
// }
