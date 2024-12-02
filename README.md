# Vocdoni Gnark Crypto Primitives

A set of custom circuits writted in [Gnark](https://github.com/ConsenSys/gnark) that are required to support anonymous voting on [Vocdoni](https://github.com/vocdoni).

## Primitives included

* Hash Poseidon ([source code](./hash/bn254/poseidon)).
* SMT Verifier port from [@iden3/circomlib](https://github.com/iden3/circomlib/blob/master/circuits/smt/smtverifier.circom) ([source code](./tree/smt)).
* Arbo (by [@arnaucube](https://github.com/arnaucube)) proof checker from [@vocdoni/arbo](https://github.com/vocdoni/vocdoni-node/tree/main/tree/arbo) ([source code](./tree/arbo))
    - This is also compatible with the circomlib SMT Verifier.
* Homomorphic Addition (using point reduction of TwistedEdwards curve to transform circom BabyJubJub points into Gnark BabyJubJub points) ([source code](./hommomorphic/add.go)) ([helpers source code](./emulated/bn254/twistededwards/twistededwards.go))
* Address derivation from ECDSA public key (hash the key coords with Keccak256 and take the last 20 bytes) ([source code](./emulated/ecdsa/address.go)).
* Some other helper functions that are useful in previous primitives ([source code](./utils))
---

## DISCLAIMER

> This repository provides proof-of-concept implementations. These implementations are for demonstration purposes only. These circuits are not audited, and this is not intended to be used as a library for production-grade applications.