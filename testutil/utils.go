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
	BaseFiled     *big.Int
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

// GenerateCensusProofForTest generates a census proof for testing purposes, it
// receives a configuration and a key-value pair to generate the proof for.
// It returns the root, key, value, and siblings of the proof. The configuration
// includes the temp directory to store the database, the number of valid
// siblings, the total number of siblings, the key length, the hash function to
// use in the merkle tree, and the base field to use in the finite field.
func GenerateCensusProofForTest(conf CensusTestConfig, ks, vs [][]byte) (*TestCensus, error) {
	defer func() {
		_ = os.RemoveAll(conf.Dir)
	}()
	database, err := pebbledb.New(db.Options{Path: conf.Dir})
	if err != nil {
		return nil, err
	}
	tree, err := arbotree.NewTree(arbotree.Config{
		Database:     database,
		MaxLevels:    conf.TotalSiblings,
		HashFunction: conf.Hash,
	})
	if err != nil {
		return nil, err
	}
	// add the key-value pairs
	for i, k := range ks {
		k = arbotree.BigToFF(conf.BaseFiled, new(big.Int).SetBytes(k)).Bytes()
		if err = tree.Add(k, vs[i]); err != nil {
			return nil, err
		}
	}
	// add random addresses
	for i := 1; i < conf.ValidSiblings; i++ {
		rk := arbotree.BigToFF(conf.BaseFiled, new(big.Int).SetBytes(util.RandomBytes(conf.KeyLen))).Bytes()
		rv := new(big.Int).SetBytes(util.RandomBytes(8)).Bytes()
		if err = tree.Add(rk, rv); err != nil {
			return nil, err
		}
	}
	// generate the proofs
	root, err := tree.Root()
	if err != nil {
		return nil, err
	}
	proofs := []*TestCensusProofs{}
	for i, k := range ks {
		_, _, siblings, exist, err := tree.GenProof(k)
		if err != nil {
			return nil, err
		}
		if !exist {
			return nil, fmt.Errorf("error building the merkle tree: key not found")
		}
		unpackedSiblings, err := arbo.UnpackSiblings(tree.HashFunction(), siblings)
		if err != nil {
			return nil, err
		}
		paddedSiblings := make([]*big.Int, conf.TotalSiblings)
		for i := 0; i < conf.TotalSiblings; i++ {
			if i < len(unpackedSiblings) {
				paddedSiblings[i] = arbo.BytesLEToBigInt(unpackedSiblings[i])
			} else {
				paddedSiblings[i] = big.NewInt(0)
			}
		}
		verified, err := arbotree.CheckProof(tree.HashFunction(), k, vs[i], root, siblings)
		if !verified {
			return nil, fmt.Errorf("error verifying the proof")
		}
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, &TestCensusProofs{
			Key:      arbo.BytesLEToBigInt(k),
			Value:    new(big.Int).SetBytes(vs[i]),
			Siblings: paddedSiblings,
		})
	}
	return &TestCensus{
		Root:   arbo.BytesLEToBigInt(root),
		Proofs: proofs,
	}, nil
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
