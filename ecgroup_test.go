package mbedtls

import (
	"log"
	"testing"
)

func TestNewGroup(t *testing.T) {
	ecp, err := NewECGroup(ECP_GROUP_SECP256K1)
	if err != nil {
		t.Fatalf(err.Error())
	}
	privKey, pubKey, err := ecp.GenKeypair()
	if err != nil {
		t.Fatalf(err.Error())
	}
	log.Println(privKey, pubKey)
}
