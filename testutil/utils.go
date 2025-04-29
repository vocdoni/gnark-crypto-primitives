package testutil

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	arbotree "github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

// CensusTestConfig is a configuration for generating a census proof for testing
// purposes. It includes the temp directory to store the database, the number of
// valid siblings, the total number of siblings, the key length, the hash
// function to use in the merkle tree, and the base field to use in the finite
// field.
type CensusTestConfig struct {
	Dir           string
	ValidSiblings int
	TotalSiblings int
	KeyLen        int
	Hash          arbotree.HashFunction
	BaseField     *big.Int
}

// TestCensusProofs is a structure to store the key, value, and siblings of a
// census proof for testing purposes.
type TestCensusProofs struct {
	Key      *big.Int
	Value    *big.Int
	Siblings []*big.Int
}

// TestCensus is a structure to store the root and proofs of a census for
// testing purposes.
type TestCensus struct {
	Root   *big.Int
	Proofs []*TestCensusProofs
}

// TestSignature is a structure to store the public key, R, S, and address of a
// signature for testing purposes.
type TestSignature struct {
	PublicKey struct {
		X, Y *big.Int
	}
	R, S    *big.Int
	Address *big.Int
}

// GenerateAccountAndSign generates an account and signs the input data. It
// returns the signature, the address, and the public key of the account.
func GenerateAccountAndSign(input []byte) (*TestSignature, error) {
	// generate ecdsa key pair (privKey and publicKey)
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	sigBin, err := crypto.Sign(input, privKey)
	if err != nil {
		return nil, err
	}
	// truncate the signature to 64 bytes (the first 32 bytes are the R value,
	// the second 32 bytes are the S value)
	sigBin = sigBin[:64]
	if valid := crypto.VerifySignature(crypto.CompressPubkey(&privKey.PublicKey), input, sigBin); !valid {
		return nil, fmt.Errorf("invalid signature")
	}

	var sig ecdsa.Signature
	if _, err := sig.SetBytes(sigBin); err != nil {
		return nil, err
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])
	// get the address from the hash of the public key (taking the last 20 bytes
	// of the Keccak-256 hash of the public key)
	address := crypto.PubkeyToAddress(privKey.PublicKey)
	return &TestSignature{
		PublicKey: struct {
			X, Y *big.Int
		}{privKey.PublicKey.X, privKey.PublicKey.Y},
		R:       r,
		S:       s,
		Address: new(big.Int).SetBytes(address.Bytes()),
	}, nil
}

// generateCensusProof is a helper function to generate a census proof for testing purposes.
func generateCensusProof(
	conf CensusTestConfig,
	ks, vs [][]byte,
	byte2Int func([]byte) *big.Int, // ← BE or LE conversion
) (*TestCensus, error) {
	// remove temp-dir afterwards
	defer func() { _ = os.RemoveAll(conf.Dir) }()

	// --- open DB & tree -------------------------------------------------------
	dbase, err := pebbledb.New(db.Options{Path: conf.Dir})
	if err != nil {
		return nil, err
	}
	tree, err := arbotree.NewTree(arbotree.Config{
		Database:     dbase,
		MaxLevels:    conf.TotalSiblings,
		HashFunction: conf.Hash,
	})
	if err != nil {
		return nil, err
	}

	// --- 1. insert the user-supplied pairs ------------------------------------
	for i, k := range ks {
		ks[i] = arbotree.BigToFF(conf.BaseField, new(big.Int).SetBytes(k)).Bytes() // canonical BE
		if err = tree.Add(ks[i], vs[i]); err != nil {
			return nil, err
		}
	}

	// --- 2. add random leaves so that some siblings are non-zero --------------
	for i := 1; i < conf.ValidSiblings; i++ {
		rk := arbotree.BigToFF(conf.BaseField,
			new(big.Int).SetBytes(util.RandomBytes(conf.KeyLen))).Bytes()
		rv := new(big.Int).SetBytes(util.RandomBytes(8)).Bytes()
		if err = tree.Add(rk, rv); err != nil {
			return nil, err
		}
	}

	// --- 3. root & proofs ------------------------------------------------------
	rootBE, err := tree.Root() // 32-byte big-endian
	if err != nil {
		return nil, err
	}

	var proofs []*TestCensusProofs
	for i, kBE := range ks {

		_, _, sibPacked, exist, err := tree.GenProof(kBE)
		if err != nil {
			return nil, err
		}
		if !exist {
			return nil, fmt.Errorf("key not found in tree")
		}

		// unpack canonical BE siblings
		unpacked, err := arbo.UnpackSiblings(tree.HashFunction(), sibPacked)
		if err != nil {
			return nil, err
		}

		// pad / convert with the caller-supplied function
		padded := make([]*big.Int, conf.TotalSiblings)
		for j := range padded {
			if j < len(unpacked) {
				padded[j] = byte2Int(unpacked[j])
			} else {
				padded[j] = big.NewInt(0)
			}
		}

		// off-chain sanity check
		if ok, _ := arbotree.CheckProof(tree.HashFunction(),
			kBE, vs[i], rootBE, sibPacked); !ok {
			return nil, fmt.Errorf("arbotree proof verification failed")
		}

		proofs = append(proofs, &TestCensusProofs{
			Key:      byte2Int(kBE),
			Value:    new(big.Int).SetBytes(vs[i]),
			Siblings: padded,
		})
	}

	return &TestCensus{
		Root:   byte2Int(rootBE),
		Proofs: proofs,
	}, nil
}

// GenerateCensusProofBE keeps every field-element **big-endian**
// (direct `SetBytes`).
func GenerateCensusProofBE(
	conf CensusTestConfig, ks, vs [][]byte,
) (*TestCensus, error) {
	return generateCensusProof(
		conf, ks, vs,
		func(b []byte) *big.Int { return new(big.Int).SetBytes(b) }, // BE
	)
}

// GenerateCensusProofLE converts every field-element to **little-endian**
// before returning it –  this is what the original function did.
func GenerateCensusProofLE(
	conf CensusTestConfig, ks, vs [][]byte,
) (*TestCensus, error) {
	return generateCensusProof(
		conf, ks, vs,
		arbo.BytesLEToBigInt, // LE
	)
}
