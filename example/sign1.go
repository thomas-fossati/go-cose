package main

import (
	"crypto/rand"
	"fmt"

	_ "crypto/sha256"

	cose "github.com/thomas-fossati/go-cose"
)

func main() {
	msg := cose.NewSign1Message()

	msg.Payload = []byte("TODO EAT token claims")

	// create a signer with a new private key
	signer, err := cose.NewSigner(cose.ES512, nil)
	if err != nil {
		fmt.Errorf("signer creation failed: %s", err)
	}

	//msg.Headers.Unprotected["kid"] = 1 // kid
	msg.Headers.Protected[1] = -36 // ECDSA w/ SHA-512

	// optional external data
	external := []byte("")

	err = msg.Sign(rand.Reader, external, *signer)
	if err != nil {
		fmt.Printf("signature creation failed: %s\n", err)
	}

	if msg.Signature == nil {
		fmt.Println("nil signature")
	}

	fmt.Printf("Signature bytes: %x", msg.Signature)

	coseSig, err := cose.Marshal(msg)
	if err != nil {
		fmt.Errorf("COSE marshaling failed: %s", err)
	}

	fmt.Printf("COSE message: %x", coseSig)
}
