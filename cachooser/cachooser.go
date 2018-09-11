// Package cachooser defines an interface for the program that chooses the CA to sign with.
package cachooser

import (
	"crypto/rsa"
	"crypto/x509"
)

// Choose the CA to be used to sign this CSR.
type CAChooser interface {
	Choose(data []byte, caKeyPass []byte) (*rsa.PrivateKey, []*x509.Certificate, error)
}
