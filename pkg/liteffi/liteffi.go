package liteffi

import (
	"fmt"
	"reflect"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

//lightweight, synchronous, value semantic FFI

func VerifyMeasurementAttestationFFI(
	trustedRootJSON, bundleJSON []byte,
	hexDigest, repo string,
) (*MeasurementFFI, error) {
	measurement, err := sigstore.VerifyAttestation(
		trustedRootJSON, bundleJSON,
		hexDigest, repo,
	)

	if err != nil { return nil, err }

	return &MeasurementFFI{
		string(measurement.Type),
		measurement.Registers,
	}, nil
}

//This is a complex network fetch
//TODO: handle this async
func FetchTrustRootFFI() ([]byte, error) {
	return sigstore.FetchTrustRoot()
}

//Obj-C FFI forces single return value
type DocumentVerifyOutput struct {
	Measurement 			*MeasurementFFI
	CertificateFingerPrint []byte
}

func VerifyDocument(documentFormat, body string) (*DocumentVerifyOutput, error) {
	inner := &attestation.Document{ attestation.PredicateType(documentFormat), body }
	measurement, cfp, err := inner.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify document: %v", err)
	}

	measurementFFI := &MeasurementFFI{
		string(measurement.Type),
		measurement.Registers,
	}

	return &DocumentVerifyOutput{measurementFFI, cfp}, nil
}

//we just need equatable
type MeasurementFFI struct {
	RawPredicateType 	string
	Registers 			[]string
}

func(m* MeasurementFFI) Equals(other *MeasurementFFI) (bool) {
	return m.RawPredicateType == other.RawPredicateType && reflect.DeepEqual(m.Registers, other.Registers )
}