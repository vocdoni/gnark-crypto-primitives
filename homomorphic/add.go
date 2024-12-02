package hadd

import (
	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func Add(api frontend.API, a, b twistededwards.Point) (twistededwards.Point, error) {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return twistededwards.Point{}, err
	}
	curve.AssertIsOnCurve(a)
	curve.AssertIsOnCurve(b)
	return curve.Add(a, b), nil
}
