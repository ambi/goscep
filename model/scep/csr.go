package scep

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

var (
	maxSerialNumber = new(big.Int).Lsh(big.NewInt(1), 128)
)

func generateSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, maxSerialNumber)
}

// SignClientCertificate creates and signs a client certificate based on a certificate request.
func SignClientCertificate(csr *x509.CertificateRequest, keypair CAKeyPair, validity time.Duration) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		// SubjectKeyId: id,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(validity),

		Subject:            csr.Subject,
		Signature:          csr.Signature, // ?
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm, // ?
		PublicKey:          csr.PublicKey,          // ?
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,

		Issuer: keypair.Certs[0].Subject, // TODO: is it necessary?

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	b, err := x509.CreateCertificate(rand.Reader, tmpl, keypair.Certs[0], csr.PublicKey, keypair.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}

	// TODO: save into depot.

	return cert, nil
}
