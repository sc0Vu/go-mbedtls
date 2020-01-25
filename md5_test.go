package mbedtls

import (
	"bytes"
	"crypto/md5"
	"testing"
)

type md5Test struct {
	src []byte
}

var md5Tests = []md5Test{
	md5Test{
		src: []byte("hello"),
	},
	md5Test{
		src: []byte(""),
	},
	md5Test{
		src: []byte{0},
	},
}

func TestMD5(t *testing.T) {
	for _, test := range md5Tests {
		cout := md5.Sum(test.src)
		mout, err := MD5(test.src)
		if err != nil {
			t.Fatal(err)
		}
		if len(cout) != len(mout) {
			t.Fatalf("md5 hash result didn't match")
		}
		if !bytes.Equal(cout[:], mout[:]) {
			t.Fatalf("md5 hash result didn't match")
		}
	}
}

func BenchmarkMD5(b *testing.B) {
	src := []byte("helloworld")
	for n := 0; n < b.N; n++ {
		MD5(src)
	}
}
