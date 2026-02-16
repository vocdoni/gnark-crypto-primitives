package hash

import "github.com/consensys/gnark/frontend"

// Hash interface allows to enforce a common API for gnark hash functions.
// It includes the basic operations such as Write, Reset and Sum, but also
// some additional methods like WriteSuccedded, SumIsEqual and AssertSumIsEqual
// that allows to compare the resulting hash with an expected value directly.
type Hash[T any] interface {
	// Basic methods
	Write(data ...T)
	Reset()
	Sum() T
	// Addiditional methods
	WriteSucceeded() bool
	SumIsEqual(expected T) frontend.Variable
	AssertSumIsEqual(expected T)
}
