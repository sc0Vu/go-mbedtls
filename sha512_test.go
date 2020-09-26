package mbedtls

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

type sha512Test struct {
	src []byte
}

var sha512Tests = []sha512Test{
	sha512Test{
		src: []byte("hello"),
	},
	sha512Test{
		src: []byte(""),
	},
	sha512Test{
		src: []byte{0},
	},
}

func TestSHA512(t *testing.T) {
	for _, test := range sha512Tests {
		cout := sha512.Sum512(test.src)
		mout, err := Sha512(test.src)
		if err != nil {
			t.Fatal(err)
		}
		if len(cout) != len(mout) {
			t.Fatalf("sha512 hash result didn't match")
		}
		if !bytes.Equal(cout[:], mout[:]) {
			t.Fatalf("sha512 hash result didn't match")
		}
	}
}

// func BenchmarkSHA512(b *testing.B) {
// 	src := []byte("helloworld")
// 	b.ResetTimer()
// 	for n := 0; n < b.N; n++ {
// 		Sha512(src)
// 	}
// }
