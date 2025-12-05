package elgamal

import (
	"math/big"
	"sync"

	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
)

// fixedBaseTable holds precomputed multiples of the base point G in 4-bit windows.
// Each entry fixedBaseTable[i][v] contains [v * 2^(4*i)] * G.
// Initialized lazily on first use.
var (
	fixedBaseTable     [][][2]*big.Int // each point as [X, Y]
	fixedBaseTableOnce sync.Once
)

// initFixedBaseTable precomputes the base table used for windowed scalar multiplication.
// It supports 254-bit scalars (BabyJubjub on BN254).
// For windows 0-62 (4 bits), it computes 16 points.
// For window 63 (2 bits), it computes 4 points.
func initFixedBaseTable() {
	const numWindows = 64 // 254 bits: 63 * 4 + 2 = 254
	fixedBaseTable = make([][][2]*big.Int, numWindows)

	// Get the BN254 twisted Edwards curve parameters
	edcurve := edbn254.GetEdwardsCurve()

	// Get base point
	var basePoint edbn254.PointAffine
	basePoint.X.Set(&edcurve.Base.X)
	basePoint.Y.Set(&edcurve.Base.Y)

	// Identity point (0, 1)
	identity := [2]*big.Int{big.NewInt(0), big.NewInt(1)}

	for i := 0; i < numWindows; i++ {
		entries := 16
		if i == numWindows-1 {
			entries = 4 // Last window covers remaining 2 bits
		}

		table := make([][2]*big.Int, entries)
		table[0] = identity

		// For window i, compute [j * 2^(4*i)] * G
		// windowMultiplier = 2^(4*i)
		windowMultiplier := new(big.Int).Lsh(big.NewInt(1), uint(4*i))

		for j := 1; j < entries; j++ {
			// scalar = j * 2^(4*i)
			scalar := new(big.Int).Mul(big.NewInt(int64(j)), windowMultiplier)

			// Compute [scalar] * G
			var point edbn254.PointAffine
			point.ScalarMultiplication(&basePoint, scalar)

			// Convert to big.Int
			xBig := new(big.Int)
			yBig := new(big.Int)
			point.X.BigInt(xBig)
			point.Y.BigInt(yBig)

			table[j] = [2]*big.Int{xBig, yBig}
		}
		fixedBaseTable[i] = table
	}
}

// FixedBaseScalarMulBN254 performs an optimized multiplication of a scalar with a fixed base (G),
// using 4-bit windowing with Lookup2 for efficient selection.
func FixedBaseScalarMulBN254(api frontend.API, scalar frontend.Variable) twistededwards.Point {
	// Initialize table on first use
	fixedBaseTableOnce.Do(initFixedBaseTable)

	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		panic(err)
	}

	// Break scalar into 254 bits total (BN254 scalar field)
	scalarBits := bits.ToBinary(api, scalar, bits.WithNbDigits(254))
	// 63 windows of 4 bits + 1 window of 2 bits
	nWindows := 64

	// Result accumulator
	var res twistededwards.Point

	for i := 0; i < nWindows; i++ {
		var px, py frontend.Variable
		table := fixedBaseTable[i]

		if i < nWindows-1 {
			// Standard 4-bit window (16 entries)
			bits4 := scalarBits[i*4 : (i+1)*4]

			// Prepare coordinates for lookup
			xValues := make([]frontend.Variable, 16)
			yValues := make([]frontend.Variable, 16)
			for j := 0; j < 16; j++ {
				xValues[j] = table[j][0]
				yValues[j] = table[j][1]
			}

			// Nested Lookup2 for 4-bit selection
			px0 := api.Lookup2(bits4[0], bits4[1], xValues[0], xValues[1], xValues[2], xValues[3])
			px1 := api.Lookup2(bits4[0], bits4[1], xValues[4], xValues[5], xValues[6], xValues[7])
			px2 := api.Lookup2(bits4[0], bits4[1], xValues[8], xValues[9], xValues[10], xValues[11])
			px3 := api.Lookup2(bits4[0], bits4[1], xValues[12], xValues[13], xValues[14], xValues[15])
			px = api.Lookup2(bits4[2], bits4[3], px0, px1, px2, px3)

			py0 := api.Lookup2(bits4[0], bits4[1], yValues[0], yValues[1], yValues[2], yValues[3])
			py1 := api.Lookup2(bits4[0], bits4[1], yValues[4], yValues[5], yValues[6], yValues[7])
			py2 := api.Lookup2(bits4[0], bits4[1], yValues[8], yValues[9], yValues[10], yValues[11])
			py3 := api.Lookup2(bits4[0], bits4[1], yValues[12], yValues[13], yValues[14], yValues[15])
			py = api.Lookup2(bits4[2], bits4[3], py0, py1, py2, py3)

			// nibble zero flag to skip adding the identity contribution
			nibZero := api.And(api.Sub(1, bits4[0]), api.Sub(1, bits4[1]))
			nibZero = api.And(nibZero, api.Sub(1, bits4[2]))
			nibZero = api.And(nibZero, api.Sub(1, bits4[3]))

			contrib := twistededwards.Point{X: px, Y: py}

			if i == 0 {
				// First window initializes the result (avoids adding identity)
				res = contrib
			} else {
				// Only add if nibble != 0 to save constraints
				// res = res + contrib when nibZero == 0, else res
				added := curve.Add(res, contrib)
				res.X = api.Select(nibZero, res.X, added.X)
				res.Y = api.Select(nibZero, res.Y, added.Y)
			}
		} else {
			// Last window (2 bits, 4 entries)
			bits2 := scalarBits[i*4 : i*4+2]

			xValues := make([]frontend.Variable, 4)
			yValues := make([]frontend.Variable, 4)
			for j := range 4 {
				xValues[j] = table[j][0]
				yValues[j] = table[j][1]
			}

			// Single Lookup2 for 2-bit selection
			px = api.Lookup2(bits2[0], bits2[1], xValues[0], xValues[1], xValues[2], xValues[3])
			py = api.Lookup2(bits2[0], bits2[1], yValues[0], yValues[1], yValues[2], yValues[3])

			nibZero := api.And(api.Sub(1, bits2[0]), api.Sub(1, bits2[1]))

			contrib := twistededwards.Point{X: px, Y: py}

			// Accumulate final window conditionally
			added := curve.Add(res, contrib)
			res.X = api.Select(nibZero, res.X, added.X)
			res.Y = api.Select(nibZero, res.Y, added.Y)
		}
	}

	return res
}
