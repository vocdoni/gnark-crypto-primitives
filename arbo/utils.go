package arbo

import (
	"fmt"
	"math/big"
	"os"

	arbotree "github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

type censusConfig struct {
	dir           string
	validSiblings int
	totalSiblings int
	keyLen        int
	hash          arbotree.HashFunction
	baseFiled     *big.Int
}

func generateCensusProof(conf censusConfig, k, v []byte) (*big.Int, *big.Int, *big.Int, []*big.Int, error) {
	defer func() {
		_ = os.RemoveAll(conf.dir)
	}()
	database, err := pebbledb.New(db.Options{Path: conf.dir})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tree, err := arbotree.NewTree(arbotree.Config{
		Database:     database,
		MaxLevels:    conf.totalSiblings,
		HashFunction: conf.hash,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	k = arbotree.BigToFF(conf.baseFiled, new(big.Int).SetBytes(k)).Bytes()
	// add the first key-value pair
	if err = tree.Add(k, v); err != nil {
		return nil, nil, nil, nil, err
	}
	// add random addresses
	for i := 1; i < conf.validSiblings; i++ {
		rk := arbotree.BigToFF(conf.baseFiled, new(big.Int).SetBytes(util.RandomBytes(conf.keyLen))).Bytes()
		rv := new(big.Int).SetBytes(util.RandomBytes(8)).Bytes()
		if err = tree.Add(rk, rv); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	// generate the proof
	_, _, siblings, exist, err := tree.GenProof(k)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !exist {
		return nil, nil, nil, nil, fmt.Errorf("error building the merkle tree: key not found")
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, siblings)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	paddedSiblings := make([]*big.Int, conf.totalSiblings)
	for i := 0; i < conf.totalSiblings; i++ {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesLEToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	root, err := tree.Root()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	verified, err := arbotree.CheckProof(tree.HashFunction(), k, v, root, siblings)
	if !verified {
		return nil, nil, nil, nil, fmt.Errorf("error verifying the proof")
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return arbo.BytesLEToBigInt(root), arbo.BytesLEToBigInt(k), new(big.Int).SetBytes(v), paddedSiblings, nil
}
