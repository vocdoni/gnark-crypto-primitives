package smt

import (
	"github.com/consensys/gnark/frontend"
)

// IsEqual returns 1 iff a == b, 0 otherwise (unchanged).
func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

// ForceEqualIfEnabledFlag returns 1 when either
//   - enabled == 0   (check bypassed),  OR
//   - enabled == 1 && a == b
//
// and returns 0 otherwise.
//
//	ok = enabled ? IsZero(a-b) : 1
func ForceEqualIfEnabledFlag(api frontend.API,
	a, b, enabled frontend.Variable,
) frontend.Variable {
	diffZero := api.IsZero(api.Sub(a, b))
	return api.Select(enabled, diffZero, 1)
}

// ForceEqualIfEnabled returns 1 when a == b, 0 otherwise, if enabled == 1.
// It is equivalent to ForceEqualIfEnabledFlag(api, a, b, 1).
func ForceEqualIfEnabled(api frontend.API, a, b, enabled frontend.Variable) {
	isEqual := ForceEqualIfEnabledFlag(api, a, b, enabled)
	api.AssertIsEqual(isEqual, 1)
}

func MultiAnd(api frontend.API, in []frontend.Variable) frontend.Variable {
	out := frontend.Variable(1)
	for i := 0; i < len(in); i++ {
		out = api.And(out, in[i])
	}
	return out
}

// Switcher returns (l,r) when sel == 0 and (r,l) when sel == 1.
func Switcher(api frontend.API,
	sel, l, r frontend.Variable,
) (frontend.Variable, frontend.Variable) {
	outL := api.Select(sel, r, l) // if sel==1 pick r else l
	outR := api.Select(sel, l, r) // if sel==1 pick l else r
	return outL, outR
}
