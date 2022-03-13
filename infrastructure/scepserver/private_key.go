package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func readRSAPrivateKeyPEM(filename, password string) (*rsa.PrivateKey, error) {
	// #nosec
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(bytes)
	if pemBlock == nil {
		return nil, errors.New("failed decoding RSA private key PEM")
	}

	b, err := x509.DecryptPEMBlock(pemBlock, []byte(password))
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(b)
}
