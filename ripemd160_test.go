package mbedtls

import (
	"testing"
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

// func TestRipemd160(t *testing.T) {
// 	for _, test := range ripemd160Tests {
// 		ghash := ripemd160.New()
// 		ghash.Write(test.src)
// 		cout := ghash.Sum(test.src)
// 		mout, err := Ripemd160(test.src)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		if len(cout) != len(mout) {
// 			t.Fatalf("ripemd160 hash result didn't match")
// 		}
// 		if !bytes.Equal(cout[:], mout[:]) {
// 			t.Fatalf("ripemd160 hash result didn't match")
// 		}
// 	}
// }

func BenchmarkRipemd160(b *testing.B) {
	src := []byte("helloworld")
	for n := 0; n < b.N; n++ {
		Ripemd160(src)
	}
}
