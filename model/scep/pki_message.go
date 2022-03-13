package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"go.mozilla.org/pkcs7"
)

const (
	// RFC8894: 3.2.1.2. messageType
	// 0 Reserved
	// 3 CertRep: Response to certificate or CRL request.
	// 17 RenewalReq: PKCS #10 certificate request authenticated with an existing certificate.
	// 19 PKCSReq: PKCS #10 certificate request authenticated with a shared secret.
	// 20 CertPoll: Certificate polling in manual enrolment.
	// 21 GetCert: Retrieve a certificate.
	// 22 GetCRL: Retrieve a CRL.

	// Reserved is reserved.
	Reserved = "0"
	// CertRep is a response to certificate or CRL request.
	CertRep = "3"
	// RenewalReq is a PKCS #10 certificate request authenticated with an existing certificate.
	RenewalReq = "17"
	// PKCSReq is a PKCS #10 certificate request authenticated with a shared secret.
	PKCSReq = "19"
	// CertPoll is certificate polling in manual enrolment.
	CertPoll = "20"
	// GetCert retrieves a certificate.
	GetCert = "21"
	// GetCRL retrieves a CRL.
	GetCRL = "22"

	// RFC8894: 3.2.1.3. pkiStatus
	// 0 SUCCESS: Request granted.
	// 2 FAILURE: Request rejected. In this case, the failInfo attribute, as defined in Section 3.2.1.4, MUST also be present.
	// 3 PENDING: Request pending for manual approval.

	// SUCCESS means a request was granted.
	SUCCESS = "0"
	// FAILURE means a request was rejected.
	FAILURE = "2"
	// PENDING means request pending for manual approval.
	PENDING = "3"

	// RFC8894: 3.2.1.4. failInfo and failInfoText
	// 0 badAlg: Unrecognised or unsupported algorithm.
	// 1 badMessageCheck: Integrity check (meaning signature verification of the CMS message) failed.
	// 2 badRequest: Transaction not permitted or supported.
	// 3 badTime: The signingTime attribute from the CMS authenticatedAttributes was not sufficiently close to the system time. This condition may occur if the CA is concerned about replays of old messages.
	// 4 badCertId: No certificate could be identified matching the provided criteria.

	// BadAlg means unrecognized or unsupported algorithm.
	BadAlg = "0"
	// BadMessageCheck means that integrity check failed.
	BadMessageCheck = "1"
	// BadRequest means that transaction was not permitted or supported.
	BadRequest = "2"
	// BadTime means that the signingTime atribute was not sufficiently close to the system time.
	BadTime = "3"
	// BadCertID means that no certificate could be identified matching the provided criteria.
	BadCertID = "4"
)

var (
	errMessageTypeNotImplemented = errors.New("messageType not implemented")
	errMessageTypeUnknown        = errors.New("unknown messageType")

	// RFC8894: 3.2.1. Signed Transaction Attributes
	// id-VeriSign | OBJECT_IDENTIFIER ::= {2 16 US(840) 1 VeriSign(113733)}
	// id-pki | OBJECT_IDENTIFIER ::= {id-VeriSign pki(1)}
	// id-attributes | OBJECT_IDENTIFIER ::= {id-pki attributes(9)}
	// id-transactionID | OBJECT_IDENTIFIER ::= {id-attributes transactionID(7)}
	// id-messageType | OBJECT_IDENTIFIER ::= {id-attributes messageType(2)}
	// id-pkiStatus | OBJECT_IDENTIFIER ::= {id-attributes pkiStatus(3)}
	// id-failInfo | OBJECT_IDENTIFIER ::= {id-attributes failInfo(4)}
	// id-senderNonce | OBJECT_IDENTIFIER ::= {id-attributes senderNonce(5)}
	// id-recipientNonce | OBJECT_IDENTIFIER ::= {id-attributes recipientNonce(6)}
	oidSCEPmessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPtransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// PKIMessage is the type of SCEP PKI messages.
// RFC8894: 3.2.1. Signed Transaction Attributes
// RFC8894: 3.2.2. SCEP pkcsPKIEnvelope
type PKIMessage struct {
	Raw []byte

	TransactionID  string
	MessageType    string
	PKIStatus      string
	FailInfo       string
	FailInfoText   string
	SenderNonce    string
	RecipientNonce string

	Certificate *x509.Certificate
	CSR         *x509.CertificateRequest
}

// ParsePKIMessage parses a PKI message in SCEP.
func ParsePKIMessage(data []byte, keypair CAKeyPair) (*PKIMessage, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}

	if err := p7.Verify(); err != nil {
		return nil, err
	}

	var msg PKIMessage

	if err := msg.parseAttributes(p7); err != nil {
		return nil, err
	}

	switch msg.MessageType {
	case CertRep:
		if err := msg.parseCertificate(p7, keypair.Certs[0], keypair.Key); err != nil { // TODO: 0 is OK?
			return nil, err
		}
	case PKCSReq, RenewalReq:
		if err := msg.parseCSR(p7, keypair.Certs[0], keypair.Key); err != nil {
			return nil, err
		}
	}

	return &msg, nil
}

// Success creates a PKI message of a success response.
func (msg *PKIMessage) Success(keypair CAKeyPair, cert *x509.Certificate) (*PKIMessage, error) {
	degenerate, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		return nil, err
	}

	e7, err := pkcs7.Encrypt(degenerate, []*x509.Certificate{msg.Certificate}) // TODO: OK?
	if err != nil {
		return nil, err
	}

	cfg := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidSCEPtransactionID, Value: msg.TransactionID},
			{Type: oidSCEPpkiStatus, Value: SUCCESS},
			{Type: oidSCEPmessageType, Value: CertRep},
			{Type: oidSCEPsenderNonce, Value: msg.SenderNonce},
			{Type: oidSCEPrecipientNonce, Value: msg.SenderNonce},
		},
	}

	signedData, err := pkcs7.NewSignedData(e7)
	if err != nil {
		return nil, err
	}

	signedData.AddCertificate(cert)

	if err := signedData.AddSigner(keypair.Certs[0], keypair.Key, cfg); err != nil {
		return nil, err
	}

	b, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	rep := &PKIMessage{
		Raw:            b,
		TransactionID:  msg.TransactionID,
		MessageType:    CertRep,
		PKIStatus:      SUCCESS,
		RecipientNonce: msg.SenderNonce,
		Certificate:    cert,
	}
	return rep, nil
}

// Failure creates a PKI message of a failure response.
func (msg *PKIMessage) Failure(keypair CAKeyPair, failInfo string) (*PKIMessage, error) {
	cfg := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidSCEPtransactionID, Value: msg.TransactionID},
			{Type: oidSCEPpkiStatus, Value: FAILURE},
			{Type: oidSCEPfailInfo, Value: failInfo},
			{Type: oidSCEPmessageType, Value: CertRep},
			{Type: oidSCEPsenderNonce, Value: msg.SenderNonce},
			{Type: oidSCEPrecipientNonce, Value: msg.SenderNonce},
		},
	}

	signedData, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}

	if err := signedData.AddSigner(keypair.Certs[0], keypair.Key, cfg); err != nil {
		return nil, err
	}

	b, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	rep := &PKIMessage{
		Raw:            b,
		TransactionID:  msg.TransactionID,
		MessageType:    CertRep,
		PKIStatus:      FAILURE,
		FailInfo:       BadRequest,
		RecipientNonce: msg.SenderNonce,
	}
	return rep, nil
}

func (msg *PKIMessage) parseAttributes(p7 *pkcs7.PKCS7) error {
	// RFC8894: 3.2.1. Signed Transaction Attributes
	// At a minimum, all messages MUST contain the following authenticatedAttributes:
	// - A transactionID attribute (see Section 3.2.1.1).
	// - A messageType attribute (see Section 3.2.1.2).
	// - A fresh senderNonce attribute (see Section 3.2.1.5). However, note the comment about senderNonces and polling in Section 3.3.2
	// - Any attributes required by CMS.
	if err := p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &msg.TransactionID); err != nil {
		return err
	}
	if err := p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msg.MessageType); err != nil {
		return err
	}
	if err := p7.UnmarshalSignedAttribute(oidSCEPsenderNonce, &msg.SenderNonce); err != nil {
		return err
	}

	switch msg.MessageType {
	case CertRep:
		// RFC8894: 3.2.1. Signed Transaction Attributes
		// If the message is a CertRep, it MUST also include the following authenticatedAttributes:
		// - A pkiStatus attribute (see Section 3.2.1.3).
		// - failInfo and optional failInfoText attributes (see Section 3.2.1.4) if pkiStatus = FAILURE.
		// - A recipientNonce attribute (see Section 3.2.1.5) copied from the senderNonce in the request that this is a response to.
		if err := p7.UnmarshalSignedAttribute(oidSCEPpkiStatus, &msg.PKIStatus); err != nil {
			return err
		}
		if msg.PKIStatus == FAILURE {
			if err := p7.UnmarshalSignedAttribute(oidSCEPfailInfo, &msg.FailInfo); err != nil {
				return err
			}
			// TODO: failInfoText
		}
		if err := p7.UnmarshalSignedAttribute(oidSCEPrecipientNonce, &msg.RecipientNonce); err != nil {
			return err
		}

	case PKCSReq, RenewalReq:
		// do nothing.
	case GetCRL, GetCert, CertPoll:
		return errMessageTypeNotImplemented
	default:
		return errMessageTypeUnknown
	}

	return nil
}

func (msg *PKIMessage) parseCertificate(p7 *pkcs7.PKCS7, cert *x509.Certificate, key *rsa.PrivateKey) error {
	envelope, err := p7.Decrypt(cert, key)
	if err != nil {
		return err
	}

	signedData, err := pkcs7.Parse(envelope)
	if err != nil {
		return err
	}

	msg.Certificate = signedData.Certificates[0] // 0 is OK?

	return nil
}

func (msg *PKIMessage) parseCSR(p7 *pkcs7.PKCS7, cert *x509.Certificate, key *rsa.PrivateKey) error {
	envelope, err := p7.Decrypt(cert, key)
	if err != nil {
		return err
	}

	msg.CSR, err = x509.ParseCertificateRequest(envelope)
	if err != nil {
		return err
	}

	// TODO: challenge password

	return nil
}
