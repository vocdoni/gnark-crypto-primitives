package eddsa

import (
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
)

// rteB8 is the reduced twisted edwards point for BabyJubJub B8, used for EdDSA
// verification
var rteB8 twistededwards.Point

func init() {
	// Convert BabyJubJub B8 to reduced twisted edwards
	x, y := format.FromTEtoRTE(babyjub.B8.X, babyjub.B8.Y)
	// Set rteB8 global variable
	rteB8 = twistededwards.Point{X: x, Y: y}
}
