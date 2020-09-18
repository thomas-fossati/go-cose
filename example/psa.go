package main

import (
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/thomas-fossati/go-cose"
)

const (
	PSA_PROFILE = "PSA_IOT_PROFILE_1"
)

type PSASwClaims struct {
	MeasurementType  string `cbor:"1,keyasint,omitempty" json:"measurement-type,omitempty"`
	MeasurementValue []byte `cbor:"2,keyasint" json:"measurement-value"`
	Version          string `cbor:"4,keyasint,omitempty" json:"version,omitempty"`
	SignerID         []byte `cbor:"5,keyasint" json:"signer-id"`
	MeasurementDesc  string `cbor:"6,keyasint,omitempty" json:"measurement-description,omitempty"`
}

type PSAClaims struct {
	Profile          string        `cbor:"-75000,keyasint" json:"profile"`
	PartitionID      int           `cbor:"-75001,keyasint" json:"partition-id"`
	LifeCycle        uint          `cbor:"-75002,keyasint" json:"life-cycle"`
	ImplID           []byte        `cbor:"-75003,keyasint" json:"implementation-id"`
	BootSeed         []byte        `cbor:"-75004,keyasint" json:"boot-seed"`
	HwVersion        string        `cbor:"-75005,keyasint,omitempty" json:"hardware-version,omitempty"`
	SwComp           []PSASwClaims `cbor:"-75006,keyasint,omitempty" json:"software-components,omitempty"`
	NoSwMeasurements uint          `cbor:"-75007,keyasint,omitempty" json:"no-software-measurements,omitempty"`
	Nonce            []byte        `cbor:"-75008,keyasint" json:"nonce"`
	InstID           []byte        `cbor:"-75009,keyasint" json:"instance-id"`
	VSI              string        `cbor:"-75010,keyasint,omitempty" json:"verification-service-indicator,omitempty"`
}

func (p PSAClaims) validate() error {
	// TODO(tho)
	return nil
}

func (p PSAClaims) ToJSON() ([]byte, error) {
	err := p.validate()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(&p, "", "  ")
}

func (p PSAClaims) ToCBOR() ([]byte, error) {
	err := p.validate()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(&p)
}

func Send(signer *cose.Signer) ([]byte, error) {
	msg := cose.NewSign1Message()

	msg.Payload, _ = makePSAClaims()
	msg.Headers.Protected[1] = -36 // alg = ECDSA w/ SHA-512

	err := msg.Sign(rand.Reader, []byte(""), *signer)
	if err != nil {
		return nil, err
	}

	psaToken, err := cose.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return psaToken, nil
}

func Recv(psaToken []byte, verifier *cose.Verifier) error {
	if !cose.IsSign1Message(psaToken) {
		return fmt.Errorf("not a COSE-Sign1 message")
	}

	msg := cose.NewSign1Message()

	err := msg.UnmarshalCBOR(psaToken)
	if err != nil {
		return err
	}

	err = msg.Verify([]byte(""), *verifier)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var psaClaims PSAClaims
	err = cbor.Unmarshal(msg.Payload, &psaClaims)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	json, _ := psaClaims.ToJSON()
	fmt.Println(string(json))

	return nil
}

func main() {
	signer, err := cose.NewSigner(cose.ES512, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	psaToken, err := Send(signer)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("exchanging PSA token: %x\n", psaToken)

	err = Recv(psaToken, signer.Verifier())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("signature verification OK")
}

func makePSAClaims() ([]byte, error) {
	psaClaims := PSAClaims{
		Profile:     PSA_PROFILE,
		PartitionID: 1,
		LifeCycle:   0x0000,
		ImplID:      []byte{0x50, 0x51, 0x52, 0x53},
		BootSeed:    []byte{0xde, 0xad, 0xbe, 0xef},
		HwVersion:   "123457890123",
		SwComp: []PSASwClaims{
			PSASwClaims{
				MeasurementType:  "BL",
				MeasurementValue: []byte{0x00, 0x01, 0x02, 0x04},
				SignerID:         []byte{0x51, 0x92, 0x00, 0xff},
			},
			PSASwClaims{
				MeasurementType:  "PRoT",
				MeasurementValue: []byte{0x05, 0x06, 0x07, 0x08},
				SignerID:         []byte{0x51, 0x92, 0x00, 0xff},
			},
		},
		Nonce:  []byte{0x00, 0x01, 0x02, 0x03},
		InstID: []byte{0xa0, 0xa1, 0xa2, 0xa3},
		VSI:    "https://psa-verifier.org",
	}

	return psaClaims.ToCBOR()
}
