package liteffi

import (
	"fmt"
	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

//lightweight, synchronous, value semantic FFI

func VerifyMeasurementAttestationFFI(
	trustedRootJSON, bundleJSON []byte,
	hexDigest, repo string,
) (*attestation.Measurement, error) {
	return sigstore.VerifyAttestation(
		trustedRootJSON, bundleJSON,
		hexDigest, repo,
	)
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
