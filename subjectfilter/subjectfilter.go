// Package subjectfilter defines an interface for the program that modifies the subject before signing.
package subjectfilter

import (
	"crypto/x509/pkix"
)

// Choose the CA to be used to sign this CSR.
type SubjectFilter interface {
	Filter(csrData []byte) (*pkix.Name, error)
}
