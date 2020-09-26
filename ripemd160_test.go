package mbedtls

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

type ripemd160Test struct {
	src []byte
}

var ripemd160Tests = []ripemd160Test{
	ripemd160Test{
		src: []byte("hello"),
	},
	ripemd160Test{
		src: []byte(""),
	},
	ripemd160Test{
		src: []byte{0},
	},
}

func TestRIPEMD160(t *testing.T) {
	for _, test := range ripemd160Tests {
		ghash := ripemd160.New()
		ghash.Write(test.src)
		cout := ghash.Sum(nil)
		mout, err := Ripemd160(test.src)
		if err != nil {
			t.Fatal(err)
		}
		if len(cout) != len(mout) {
			t.Fatalf("ripemd160 hash result didn't match")
		}
		if !bytes.Equal(cout[:], mout[:]) {
			t.Fatalf("ripemd160 hash result didn't match")
		}
		ghash.Reset()
	}
}

// func BenchmarkRIPEMD160(b *testing.B) {
// 	src := []byte("helloworld")
// 	b.ResetTimer()
// 	for n := 0; n < b.N; n++ {
// 		Ripemd160(src)
// 	}
// }
