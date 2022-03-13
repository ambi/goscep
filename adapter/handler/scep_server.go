package handler

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/ambi/goscep/model/scep"

	"github.com/labstack/echo/v4"
	"go.mozilla.org/pkcs7"
)

const (
	withCharsetUTF8 = "; charset=UTF-8"

	contentTypePKIMessage   = "application/x-pki-message" + withCharsetUTF8
	contentTypeX509CACert   = "application/x-x509-ca-cert" + withCharsetUTF8
	contentTypeX509CARACert = "application/x-x509-ca-ra-cert" + withCharsetUTF8
	contentTypeTextPlain    = "text/plain" + withCharsetUTF8

	messageInvalidRequest   = "invalid request"
	messageMissingCACerts   = "missing CA certs"
	messageSystemError      = "system error"
	messageUnknownOperation = "unknown operation"
)

// SCEPServer is the type of SCEP servers.
type SCEPServer struct {
	CACaps    scep.CACaps
	CAKeyPair scep.CAKeyPair
}

func (srv *SCEPServer) run(c echo.Context, req *scep.Request) error {
	if err := req.Validate(); err != nil {
		return c.Blob(http.StatusBadRequest, contentTypeTextPlain, []byte(messageInvalidRequest))
	}

	switch req.Operation {
	case scep.GetCACaps:
		return srv.getCACaps(c)
	case scep.GetCACert:
		return srv.getCACert(c)
	case scep.PKIOperation:
		return srv.pkiOperation(c, req)
	}

	return c.Blob(http.StatusBadRequest, contentTypeTextPlain, []byte(messageUnknownOperation))
}

func (srv *SCEPServer) getCACaps(c echo.Context) error {
	// RFC8894: 3.5.2. CA Capabilities Response Format
	return c.Blob(http.StatusOK, contentTypeTextPlain, []byte(srv.CACaps.ToResponseFormat()))
}

func (srv *SCEPServer) getCACert(c echo.Context) error {
	if len(srv.CAKeyPair.Certs) == 0 {
		return c.Blob(http.StatusInternalServerError, contentTypeTextPlain, []byte(messageMissingCACerts))
	}

	// RFC8894: 4.2.1.1. CA Certificate Response Message Format
	if len(srv.CAKeyPair.Certs) == 1 {
		return c.Blob(http.StatusOK, contentTypeX509CACert, srv.CAKeyPair.Certs[0].Raw)
	}

	// RFC8894: 4.2.1.2. CA Certificate Chain Response Message Format
	degenerate, err := generatePKCS7(srv.CAKeyPair.Certs)
	if err != nil {
		return c.Blob(http.StatusInternalServerError, contentTypeTextPlain, []byte(messageMissingCACerts))
	}

	return c.Blob(http.StatusOK, contentTypeX509CARACert, degenerate)
}

func (srv *SCEPServer) pkiOperation(c echo.Context, req *scep.Request) error {
	msg, err := scep.ParsePKIMessage(req.Message, srv.CAKeyPair)
	if err != nil {
		return srv.systemError(c)
	}

	switch msg.MessageType {
	case scep.PKCSReq, scep.RenewalReq:
		// RFC8894: 4.3.1. Certificate Enrolment/Renewal Response Message
		var rep *scep.PKIMessage
		var err error

		cert, err := scep.SignClientCertificate(msg.CSR, srv.CAKeyPair, 360*24*time.Hour)
		if err != nil {
			rep, err = msg.Failure(srv.CAKeyPair, scep.BadRequest) // TODO: BadRequest is OK?
		} else {
			rep, err = msg.Success(srv.CAKeyPair, cert)
		}
		if err != nil {
			return srv.systemError(c)
		}

		return c.Blob(http.StatusOK, contentTypePKIMessage, rep.Raw)
	default:
		return c.Blob(http.StatusBadRequest, contentTypeTextPlain, []byte(messageUnknownOperation))
	}
}

func (srv *SCEPServer) systemError(c echo.Context) error {
	return c.Blob(http.StatusInternalServerError, contentTypeTextPlain, []byte(messageSystemError))
}

func generatePKCS7(certs []*x509.Certificate) ([]byte, error) {
	rawCerts := make([][]byte, len(certs))
	for i, cert := range certs {
		rawCerts[i] = cert.Raw
	}

	return pkcs7.DegenerateCertificate([]byte(bytes.Join(rawCerts, []byte("\n"))))
}
