package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
	"runtime"
)

const (
	ECP_GROUP_SECP192R1 = iota
	ECP_GROUP_SECP224R1
	ECP_GROUP_SECP256R1
	ECP_GROUP_SECP384R1
	ECP_GROUP_SECP521R1
	ECP_GROUP_BP256R1
	ECP_GROUP_BP384R1
	ECP_GROUP_BP512R1
	ECP_GROUP_CURVE25519
	ECP_GROUP_SECP192K1
	ECP_GROUP_SECP224K1
	ECP_GROUP_SECP256K1
	ECP_GROUP_CURVE448
)

type ECGroup struct {
	mdCurve C.mbedtls_ecp_group_id
	mdGroup *C.mbedtls_ecp_group
}

// NewECGroup returns ecp group for the given ec curve
func NewECGroup(curve int) (group *ECGroup, err error) {
	switch curve {
	case ECP_GROUP_SECP192R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP192R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP224R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP224R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP256R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP256R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP384R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP384R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP521R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP521R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_BP256R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_BP256R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_BP384R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_BP384R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_BP512R1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_BP512R1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_CURVE25519:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_CURVE25519,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP192K1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP192K1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP224K1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP224K1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_SECP256K1:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_SECP256K1,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	case ECP_GROUP_CURVE448:
		group = &ECGroup{
			mdCurve: C.MBEDTLS_ECP_DP_CURVE448,
			mdGroup: &C.mbedtls_ecp_group{},
		}
	default:
		err = ErrCurveNotSupported
		return
	}
	C.mbedtls_ecp_group_init(group.mdGroup)
	C.mbedtls_ecp_group_load(group.mdGroup, group.mdCurve)
	runtime.SetFinalizer(group, func(ecGroup *ECGroup) {
		ecGroup.Close()
	})
	return
}

// GenKeypair returns private key and public key for the ec group
// TODO: PrivateKey/PublicKey struct
func (ecGroup *ECGroup) GenKeypair() (privKey []byte, pubKey []byte, err error) {
	d := &C.mbedtls_mpi{}
	q := &C.mbedtls_ecp_point{}
	C.mbedtls_mpi_init(d)
	C.mbedtls_ecp_point_init(q)
	runtime.SetFinalizer(d, func (d *C.mbedtls_mpi) {
		C.mbedtls_mpi_free(d)
	})
	runtime.SetFinalizer(q, func (q *C.mbedtls_ecp_point) {
		C.mbedtls_ecp_point_free(q)
	})
	if ret := C.X_ec_gen_key(ecGroup.mdGroup, d, q); ret != 0 {
		err = GetECPErrorByErrorCode(int(ret))
		return
	}
	privKey = make([]byte, 32)
	C.mbedtls_mpi_write_binary(d, (*C.uchar)(unsafe.Pointer(&privKey[0])), 32)
	// MBEDTLS_ECP_PF_COMPRESSED or MBEDTLS_ECP_PF_UNCOMPRESSED
	pubKey = make([]byte, 65)
	pubKeyLen := 65
	C.mbedtls_ecp_point_write_binary(ecGroup.mdGroup, q, C.MBEDTLS_ECP_PF_UNCOMPRESSED, (*C.ulong)(unsafe.Pointer(&pubKeyLen)), (*C.uchar)(unsafe.Pointer(&pubKey[0])), 65)
	return
}

// Close the ecp group
func (ecGroup *ECGroup) Close() {
	C.mbedtls_ecp_group_free(ecGroup.mdGroup)
}
