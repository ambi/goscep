package scep

import (
	"crypto/rsa"
	"crypto/x509"
)

// CAKeyPair is the type of a CA certificate chain and a key.
type CAKeyPair struct {
	Certs []*x509.Certificate
	Key   *rsa.PrivateKey
}
