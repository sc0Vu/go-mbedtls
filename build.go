// *build

package mbedtls

// #cgo darwin CFLAGS: -I /usr/local/include
// #cgo darwin LDFLAGS: -L /usr/local/lib -lmbedtls -lmbedcrypto -lmbedx509
import "C"
