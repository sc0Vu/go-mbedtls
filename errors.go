package mbedtls

import (
	"fmt"
)

const (
	// Error code for shim
	ERR_FUNCTION_NOT_SUPPORTED = -0x1111
	// Error code for mbedtls md feature
	// -0x5080 The selected feature is not available.
	// -0x5100 Bad input parameters to function.
	// -0x5180 Failed to allocate memory.
	// -0x5200 Opening or reading of file failed.
	//
	// MBEDTLS_ERR_MD_HW_ACCEL_FAILED is deprecated and should not be used.
	// -0x5280 MD hardware accelerator failed.
	ERR_MD_FEATURE_UNAVAILABLE = -0x5080
	ERR_MD_BAD_INPUT_DATA      = -0x5100
	ERR_MD_ALLOC_FAILED        = -0x5180
	ERR_MD_FILE_IO_ERROR       = -0x5200
	ERR_MD_HW_ACCEL_FAILED     = -0x5280
)

var (
	ErrUnknownErrorCode          = fmt.Errorf("unknown error code")
	ErrFunctionNotSupported      = fmt.Errorf("couldn't find the functino in mbedtls library")
	ErrMDFeatureUnavailable      = fmt.Errorf("the selected feature is not available")
	ErrMDBadInputData            = fmt.Errorf("bad input parameters to function")
	ErrMDAllocFailed             = fmt.Errorf("failed to allocate memory")
	ErrMDFileIOError             = fmt.Errorf("opening or reading of file failed")
	ErrMDHWAccelFailed           = fmt.Errorf("MD hardware accelerator failed")
	ErrHashAlgorithmNotSupported = fmt.Errorf("hash algorithm not supported")
)

// MessageDigestError returns error for the given error code
func GetMessageDigestErrorByErrorCode(errCode int) (err error) {
	switch errCode {
	case ERR_FUNCTION_NOT_SUPPORTED:
		err = ErrFunctionNotSupported
		break
	case ERR_MD_FEATURE_UNAVAILABLE:
		err = ErrMDFeatureUnavailable
		break
	case ERR_MD_BAD_INPUT_DATA:
		err = ErrMDBadInputData
		break
	case ERR_MD_FILE_IO_ERROR:
		err = ErrMDFileIOError
		break
	case ERR_MD_ALLOC_FAILED:
		err = ErrMDAllocFailed
		break
	default:
		err = nil
		break
	}
	return err
}
