// eddsa package contains the implementation of a EdDSA signature verifier
// compatible with Iden3 and Circomlib scheme in Gnark.
package eddsa

import (
	"fmt"

	ecc_tw "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/vocdoni/gnark-crypto-primitives/ecc/format"
	"github.com/vocdoni/gnark-crypto-primitives/hash"
)

// Verifier implements a EdDSA signature verifier compatible with Iden3 and
// Circomlib scheme in Gnark.
type Verifier struct {
	api    frontend.API
	curve  twistededwards.Curve
	hashFn hash.Hash[frontend.Variable]
}

// NewVerifier returns a new instance of the Verifier using the in-ciruit API
// to initialize the twistededwards curve and the desired hash function. It
// works with Mimc7 and Poseidon hash functions.
func NewVerifier(api frontend.API, hashFn hash.Hash[frontend.Variable]) (*Verifier, error) {
	curve, err := twistededwards.NewEdCurve(api, ecc_tw.BN254)
	if err != nil {
		return nil, fmt.Errorf("error initializing bn254 twistededwards curve: %w", err)
	}
	return &Verifier{
		api:    api,
		curve:  curve,
		hashFn: hashFn,
	}, nil
}

// PointToRTE converts a twisted edwards point from the TE format to the RTE
// format. It works with the in-circuit API.
func (v *Verifier) PointToRTE(p twistededwards.Point) twistededwards.Point {
	xRTE, yRTE := format.FromTEtoRTE(v.api, p.X, p.Y)
	newPoint := twistededwards.Point{
		X: xRTE,
		Y: yRTE,
	}
	v.curve.AssertIsOnCurve(newPoint)
	return newPoint
}

// IsValid returns 1 if the signature is valid, 0 otherwise. It receives the
// public key, the signature and the message and works. It calculates the
// hash of the signature R, public key A and message using the original points
// format. Then it converts the public key A and signature R to the RTE format.
// Finally it performs the verification.
func (v *Verifier) IsValid(pubKey PublicKey, sig Signature, msg frontend.Variable) frontend.Variable {
	// Calculate the hash of the signature R, public key A and message using
	// original points format
	v.hashFn.Reset()
	v.hashFn.Write(sig.R.X, sig.R.Y, pubKey.A.X, pubKey.A.Y, msg)
	if !v.hashFn.WriteSucceeded() {
		// This point should never be reached, but if it is, return 0 as a
		// invalid signature result flag.
		return 0
	}

	// Convert the public key A and signature R to the RTE format
	rtePubKeyA := v.PointToRTE(pubKey.A)
	rteSigR := v.PointToRTE(sig.R)

	// left := sig.S * rteB8
	left := v.curve.ScalarMul(rteB8, sig.S)

	// R1 := rtePubKeyA * h * 8
	R1 := v.curve.ScalarMul(rtePubKeyA, v.hashFn.Sum()) // rtePubKeyA * h
	R1 = v.curve.Double(R1)                             // R1 * 2
	R1 = v.curve.Double(R1)                             // (R1 * 2) * 2
	R1 = v.curve.Double(R1)                             // ((R1 * 2) * 2) * 2

	// right := R1 + rteSigR
	right := v.curve.Add(R1, rteSigR)

	// Check if left == right
	xValid := v.api.IsZero(v.api.Sub(left.X, right.X))
	yValid := v.api.IsZero(v.api.Sub(left.Y, right.Y))

	// Return if both sides are valid
	return v.api.And(xValid, yValid)
}

// Verify method asserts that the public key verifies the signature for the
// message provided.
func (v *Verifier) Verify(pubKey PublicKey, sig Signature, msg frontend.Variable) {
	v.api.AssertIsEqual(v.IsValid(pubKey, sig, msg), 1)
}
