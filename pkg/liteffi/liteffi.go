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

//hacky way to re-export
type DocumentFFI struct {
	Inner attestation.Document
}

//Obj-C FFI forces single return value
type DocumentVerifyOutput struct {
	Measurement 			attestation.Measurement
	CertificateFingerPrint []byte
}

func (d* DocumentFFI) Verify() (*DocumentVerifyOutput, error) {
	measurement, cfp, err := d.Inner.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify document: %v", err)
	}

	return &DocumentVerifyOutput{*measurement, cfp}, nil
}

//we just need equatable
type MeasurementFFI struct {
	RawPredicateType 	string
	Registers 			[]string
}

func(m* MeasurementFFI) Equals(other *MeasurementFFI) (bool) {
	return m.RawPredicateType != other.RawPredicateType && reflect.DeepEqual(m.Registers, other.Registers )
}