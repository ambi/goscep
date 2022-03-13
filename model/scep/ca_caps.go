package scep

import "strings"

const (
	caCapsSeparator = "\n"
	maxCACaps       = 9
)

// CACaps is a set of CA capabilities in SCEP.
type CACaps struct {
	AES              bool
	DES3             bool
	GetNextCACert    bool
	POSTPKIOperation bool
	Renewal          bool
	SHA1             bool
	SHA256           bool
	SHA512           bool
	SCEPStandard     bool
}

// ToResponseFormat converts to the SCEP response format.
// RFC8894: 3.5.2. CA Capabilities Response Format
func (caps *CACaps) ToResponseFormat() string {
	array := make([]string, 0, maxCACaps)

	if caps.AES {
		array = append(array, "AES")
	}
	if caps.DES3 {
		array = append(array, "DES3")
	}
	if caps.GetNextCACert {
		array = append(array, "GetNextCACert")
	}
	if caps.POSTPKIOperation {
		array = append(array, "POSTPKIOperation")
	}
	if caps.Renewal {
		array = append(array, "Renewal")
	}
	if caps.SHA1 {
		array = append(array, "SHA1")
	}
	if caps.SHA256 {
		array = append(array, "SHA256")
	}
	if caps.SHA512 {
		array = append(array, "SHA512")
	}
	if caps.SCEPStandard {
		array = append(array, "SCEPStandard")
	}

	return strings.Join(array, caCapsSeparator)
}
