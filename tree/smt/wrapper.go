package smt

import (
	"math/big"

	"go.vocdoni.io/dvote/db"
)

// Wrapper defines methods for wrapping existing SMT implementations, useful for
// generating circuit assignments for generating proof witnesses. See WrapperArbo
// for a concrete example that wrappers the arbo.Tree implementation.
type Wrapper interface {
	Proof(key *big.Int) (Assignment, error)
	ProofWithTx(tx db.Reader, key *big.Int) (Assignment, error)
	SetProof(key, value *big.Int) (Assignment, error)
	Set(key, value *big.Int) (Assignment, error)
	SetWithTx(tx db.WriteTx, key, value *big.Int) (Assignment, error)
}

type Assignment struct {
	Fnc0     uint8
	Fnc1     uint8
	OldKey   *big.Int
	NewKey   *big.Int
	IsOld0   uint8
	OldValue *big.Int
	NewValue *big.Int
	OldRoot  *big.Int
	NewRoot  *big.Int
	Siblings []*big.Int
}
