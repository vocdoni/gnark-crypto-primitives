# Vocdoni Gnark Crypto Primitives

A set of custom circuits writted in [Gnark](https://github.com/ConsenSys/gnark) that are required to support anonymous voting on [Vocdoni](https://github.com/vocdoni).

## Libs included

1. Hash Poseidon ([source code](./poseidon)).
2. SMT Verifier port from [@iden3/circomlib](https://github.com/iden3/circomlib/blob/master/circuits/smt/smtverifier.circom) ([source code](./smt)).
3. Arbo (by [@arnaucube](https://github.com/arnaucube)) proof checker from [@vocdoni/arbo](https://github.com/vocdoni/vocdoni-node/tree/main/tree/arbo) ([source code](./arbo))
    - This is compatible with the SMT Verifier.


**SMT Verifier vs. Arbo**

| | SMT Verifier | Arbo |
|:---:|---:|---:|
| *Inputs* | 4 | 5 |
| *Constrains* | 42316 | 39396 (🏆) |
| *Test time* | 169.192292ms (🏆) | 172.639375ms |


---

## DISCLAIMER

> This repository provides proof-of-concept implementations. These implementations are for demonstration purposes only. These circuits are not audited, and this is not intended to be used as a library for production-grade applications.