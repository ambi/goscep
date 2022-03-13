package scep

import "fmt"

const (
	// GetCACaps is the operation to get CA capabilities.
	// RFC8894: 3.5.1. GetCACaps HTTP Message Format
	GetCACaps = "GetCACaps"
	// GetCACert is the operation to get a CA certificate.
	// RFC8894: 4.2. Get CA Certificate
	GetCACert = "GetCACert"
	// PKIOperation is the operation to perform a certificate enrolment or renewal transaction.
	// RFC8894: 4.3. Certificate Enrolment/Renewal
	PKIOperation = "PKIOperation"
)

var (
	// Operations is an array of all SCEP operations.
	Operations = []string{GetCACaps, GetCACert, PKIOperation}
)

// Request is a SCEP request (operation and message).
type Request struct {
	Operation string
	Message   []byte
}

// Validate validates a SCEP request. Messages are not validated (Use ParsePKIMessage()).
func (req *Request) Validate() error {
	if !req.validOperation() {
		return fmt.Errorf("unknown operation: %s", req.Operation)
	}

	return nil
}

func (req *Request) validOperation() bool {
	for _, ope := range Operations {
		if req.Operation == ope {
			return true
		}
	}
	return false
}
