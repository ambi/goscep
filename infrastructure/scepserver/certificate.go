package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func readCertificatePEM(filename string) (*x509.Certificate, error) {
	// #nosec
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(bytes)
	if pemBlock == nil {
		return nil, errors.New("failed decoding certificate PEM")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}
