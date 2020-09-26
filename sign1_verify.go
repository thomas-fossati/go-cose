package cose

import (
	"crypto"
	"io"

	"github.com/pkg/errors"
)

// Sign1Message represents a COSE_Sign1 message:
//
// COSE_Sign1 = [
//     Headers,
//     payload : bstr / nil,
//     signature : bstr
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.2
type Sign1Message struct {
	Headers   *Headers
	Payload   []byte
	Signature []byte
}

// NewSign1Message returns a pointer to a new, empty Sign1Message
func NewSign1Message() *Sign1Message {
	return &Sign1Message{
		Headers: &Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{},
		},
		Payload:   nil,
		Signature: nil,
	}
}

// Verify verifies the signature on the Sign1Message returning nil for
// success or an error from the failed verification
func (m *Sign1Message) Verify(external []byte, verifier Verifier) (err error) {
	// TODO(tho) check preconditions

	alg, err := getAlg(m.Headers)
	if err != nil {
		return err
	}
	if alg.Value > -1 {
		return ErrInvalidAlg
	}

	digest, err := m.signatureDigest(external, alg.HashFunc)
	if err != nil {
		return err
	}

	err = verifier.Verify(digest, m.Signature)
	if err != nil {
		return err
	}

	return nil
}

// Sign signs a Sign1Message, i.e. it populates Signature using the provided Signer
func (m *Sign1Message) Sign(rand io.Reader, external []byte, signer Signer) (err error) {
	// TODO(tho) check preconditions

	alg, err := getAlg(m.Headers)
	if err != nil {
		return err
	}
	if alg.Value > -1 {
		// TODO(tho) check if IMPDEF or as per spec.
		// Comment around LN:236 states "Negative numbers are used for
		// second layer objects (COSE_Signature and COSE_recipient)"
		return ErrInvalidAlg
	}

	// compute digest given alg
	digest, err := m.signatureDigest(external, alg.HashFunc)
	if err != nil {
		return err
	}

	if alg.Value != signer.alg.Value {
		return errors.Errorf("Signer of type %s cannot generate a signature of type %s", signer.alg.Name, alg.Name)
	}

	signatureBytes, err := signer.Sign(rand, digest)
	if err != nil {
		return err
	}

	m.Signature = signatureBytes

	return nil
}

// SigStructure returns the byte slice to be signed
func (m *Sign1Message) SigStructure(external []byte) ([]byte, error) {
	return buildAndMarshalSigStructure(
		ContextSignature1,
		m.Headers.EncodeProtected(),
		// protected attributes from the signer structure field are not
		// used in Sign1.  The third argument to buildAndMarshalSigStructure
		// is ignored.
		nil,
		external,
		m.Payload)
}

func (m *Sign1Message) signatureDigest(external []byte, hashFunc crypto.Hash) (digest []byte, err error) {
	toBeSigned, err := m.SigStructure(external)
	if err != nil {
		return nil, err
	}

	digest, err = hashSigStructure(toBeSigned, hashFunc)
	if err != nil {
		return nil, err
	}

	return digest, err
}
