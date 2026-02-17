package eddsa

import (
	"math/big"

	ecc_tw "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

// PublicKey is the public key of an EDDSA key pair
type PublicKey struct {
	A twistededwards.Point
}

// Signature is an EDDSA signature
type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

// PublicKeyFromIden3 converts a Iden3 public key to a gnark public key. It
// just creates a twisted edwards point with the x and y coordinates of the
// original public key.
func PublicKeyFromIden3(pubKey *babyjub.PublicKey) PublicKey {
	// Return the public key
	return PublicKey{
		A: twistededwards.Point{X: pubKey.X, Y: pubKey.Y},
	}
}

// SignatureFromIden3 converts a Iden3 signature to a gnark signature. It
// just creates a twisted edwards point with the x and y coordinates of the
// original signature for the R component and reduces the S component module
// with the gnark BN254 curve order.
func SignatureFromIden3(sig *babyjub.Signature) Signature {
	// Reduce S module the curve order to prevent ScalarMulFakeGLV failure
	curveParams, err := twistededwards.GetCurveParams(ecc_tw.BN254)
	if err != nil {
		panic(err)
	}
	s := new(big.Int).Mod(sig.S, curveParams.Order)
	// Return the signature with the reduced S
	return Signature{
		R: twistededwards.Point{X: sig.R8.X, Y: sig.R8.Y},
		S: s,
	}
}
