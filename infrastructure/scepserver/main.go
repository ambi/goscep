package main

import (
	"crypto/x509"
	"log"

	"github.com/labstack/echo/v4"

	"github.com/ambi/goscep/adapter/handler"
	"github.com/ambi/goscep/model/scep"
)

const (
	scepPath = "/scep"
)

var (
	defaultCACaps = scep.CACaps{
		AES:              true,
		DES3:             true,
		GetNextCACert:    false, // TODO
		POSTPKIOperation: true,
		Renewal:          true,
		SHA1:             true,
		SHA256:           true,
		SHA512:           false, // TODO
		SCEPStandard:     true,
	}
)

func main() {
	caCert, err := readCertificatePEM("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	caKey, err := readRSAPrivateKeyPEM("ca.key", "") // TODO: password
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()

	// RFC8894: 4.1. HTTP POST and GET Message Formats
	// POSTREQUEST = "POST" SP SCEPPATH "?operation=" OPERATION SP HTTP-version CRLF
	// GETREQUEST = "GET" SP SCEPPATH "?operation=" OPERATION "&message=" MESSAGE SP HTTP-version CRLF
	srv := &handler.SCEPServer{
		CACaps: defaultCACaps,
		CAKeyPair: scep.CAKeyPair{
			Certs: []*x509.Certificate{caCert},
			Key:   caKey,
		},
	}
	e.POST(scepPath, srv.POST)
	e.GET(scepPath, srv.GET)

	log.Fatal(e.Start(":8080"))
}
