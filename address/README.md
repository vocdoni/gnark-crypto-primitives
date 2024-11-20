# Ethereum Address derivation

Allows to derive the Ethereum address from a ECDSA public key.

### Test
```sh
go test -timeout 30s -run ^TestAddressDerivation$ github.com/vocdoni/gnark-crypto-primitives/address -v -count=1
```

### Info
| Metric | Value |
|:---|:---:|
| Compilation time | 1.22s |
| Constrains | 192108 |
| Proving time | 2.55s |