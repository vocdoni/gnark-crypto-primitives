package smt

import (
	"errors"
	"math/big"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/tree/arbo"
)

// WrapperArbo wraps an arbo.Tree, generating circuit assignments for certain
// tree operations like Add and Update.
type WrapperArbo struct {
	*arbo.Tree
	database db.Database
	levels   uint8
}

func NewWrapperArbo(tree *arbo.Tree, database db.Database, levels uint8) Wrapper {
	return &WrapperArbo{
		Tree:     tree,
		database: database,
		levels:   levels,
	}
}

func (t *WrapperArbo) Proof(key *big.Int) (Assignment, error) {
	return t.ProofWithTx(t.database, key)
}

func (t *WrapperArbo) ProofWithTx(tx db.Reader, key *big.Int) (Assignment, error) {
	assignment := Assignment{
		NewKey: key,
	}

	rootBytes, err := t.RootWithTx(tx)
	if err != nil {
		return assignment, err
	}
	assignment.OldRoot = arbo.BytesToBigInt(rootBytes)
	assignment.NewRoot = arbo.BytesToBigInt(rootBytes)

	bLen := t.HashFunction().Len()
	keyBytes := arbo.BigIntToBytes(bLen, key)
	oldKeyBytes, oldValueBytes, siblingsPacked, exists, err := t.GenProofWithTx(tx, keyBytes)
	if err != nil {
		return assignment, err
	}

	if exists {
		assignment.Fnc0 = 0
		assignment.NewValue = arbo.BytesToBigInt(oldValueBytes)
	} else {
		assignment.Fnc0 = 1
	}
	assignment.OldKey = arbo.BytesToBigInt(oldKeyBytes)
	assignment.OldValue = arbo.BytesToBigInt(oldValueBytes)
	if len(oldKeyBytes) > 0 {
		assignment.IsOld0 = 0
	} else {
		assignment.IsOld0 = 1
	}

	siblingsUnpacked, err := arbo.UnpackSiblings(t.HashFunction(), siblingsPacked)
	if err != nil {
		return assignment, err
	}

	assignment.Siblings = make([]*big.Int, t.levels)
	for i := 0; i < len(assignment.Siblings); i++ {
		if i < len(siblingsUnpacked) {
			assignment.Siblings[i] = arbo.BytesToBigInt(siblingsUnpacked[i])
		} else {
			assignment.Siblings[i] = big.NewInt(0)
		}
	}

	return assignment, nil
}

func (t *WrapperArbo) SetProof(key, value *big.Int) (Assignment, error) {
	tx := t.database.WriteTx()
	defer tx.Discard()
	return t.SetWithTx(tx, key, value)
}

func (t *WrapperArbo) Set(key, value *big.Int) (Assignment, error) {
	tx := t.database.WriteTx()
	defer tx.Discard()
	assignment, err := t.SetWithTx(tx, key, value)
	if err == nil {
		err = tx.Commit()
	}
	return assignment, err
}

func (t *WrapperArbo) SetWithTx(tx db.WriteTx, key, value *big.Int) (Assignment, error) {
	return t.addOrUpdate(tx, key, value, func(k, v []byte, exists bool, assignment *Assignment) error {
		if exists {
			return t.update(tx, k, v, exists, assignment)
		} else {
			return t.add(tx, k, v, exists, assignment)
		}
	})
}

func (t *WrapperArbo) add(tx db.WriteTx, k, v []byte, _ bool, assignment *Assignment) error {
	assignment.Fnc0 = 1
	assignment.Fnc1 = 0
	return t.Tree.AddWithTx(tx, k, v)
}

func (t *WrapperArbo) update(tx db.WriteTx, k, v []byte, _ bool, assignment *Assignment) error {
	assignment.Fnc0 = 0
	assignment.Fnc1 = 1
	return t.Tree.UpdateWithTx(tx, k, v)
}

func (t *WrapperArbo) addOrUpdate(tx db.WriteTx, key, value *big.Int, action func(k, v []byte, exists bool, assignment *Assignment) error) (Assignment, error) {
	assignment := Assignment{
		NewKey:   key,
		NewValue: value,
	}

	oldRootBytes, err := t.RootWithTx(tx)
	if err != nil {
		return assignment, err
	}
	assignment.OldRoot = arbo.BytesToBigInt(oldRootBytes)

	bLen := t.HashFunction().Len()
	keyBytes := arbo.BigIntToBytes(bLen, key)
	valueBytes := arbo.BigIntToBytes(bLen, value)

	oldKeyBytes, oldValueBytes, err := t.Tree.GetWithTx(tx, keyBytes)
	if err != nil && !errors.Is(err, arbo.ErrKeyNotFound) {
		return assignment, err
	}
	err = action(keyBytes, valueBytes, err == nil, &assignment)
	if err != nil {
		return assignment, err
	}

	assignment.OldKey = arbo.BytesToBigInt(oldKeyBytes)
	assignment.OldValue = arbo.BytesToBigInt(oldValueBytes)
	if len(oldKeyBytes) > 0 {
		assignment.IsOld0 = 0
	} else {
		assignment.IsOld0 = 1
	}

	newRootBytes, err := t.RootWithTx(tx)
	if err != nil {
		return assignment, err
	}
	assignment.NewRoot = arbo.BytesToBigInt(newRootBytes)

	_, _, siblingsPacked, exists, err := t.GenProofWithTx(tx, keyBytes)
	if !exists {
		return assignment, errors.New("key not found")
	}
	if err != nil {
		return assignment, err
	}

	siblingsUnpacked, err := arbo.UnpackSiblings(t.HashFunction(), siblingsPacked)
	if err != nil {
		return assignment, err
	}
	if assignment.IsOld0 == 0 && assignment.Fnc1 == 0 {
		siblingsUnpacked = siblingsUnpacked[0 : len(siblingsUnpacked)-1]
	}

	assignment.Siblings = make([]*big.Int, t.levels)
	for i := 0; i < len(assignment.Siblings); i++ {
		if i < len(siblingsUnpacked) {
			assignment.Siblings[i] = arbo.BytesToBigInt(siblingsUnpacked[i])
		} else {
			assignment.Siblings[i] = big.NewInt(0)
		}
	}

	return assignment, nil
}
