package mbedtls

import (
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

func TestSha1(t *testing.T) {
	for _, test := range sha1Tests {
		cout := sha1.Sum(test.src)
		mout, err := Sha1(test.src)
		if err != nil {
			t.Fatal(err)
		}
		if len(cout) != len(mout) {
			t.Fatalf("sha1 hash result didn't match")
		}
		for ind, byt := range cout {
			if byt != mout[ind] {
				t.Fatalf("sha1 hash result didn't match")
			}
		}
	}
}
