# Twisted Edwards format transformation

Provides helper circuit functions to transform points (x, y) from the TwistedEdwards format to Reduced TwistedEdwards format and vice versa, over BabyJubJub curve. These functions are required because Gnark uses the Reduced TwistedEdwards formula while Iden3 uses the standard TwistedEdwards formula.

Read more about this here: https://github.com/bellesmarta/baby_jubjub

### Test
```sh
go test -timeout 30s -run ^TestFromTwistedEdwards$ github.com/vocdoni/gnark-crypto-primitives/hadd -v -count=1

# or go test -timeout 30s -run ^TestFromReducedTwistedEdwards$ github.com/vocdoni/gnark-crypto-primitives/twistededwards -v -count=1
```

### Info
| Metric | Value |
|:---|:---:|
| Compilation time | 417.25µs |
| Constrains | 2 |
| Proving time | 521.334µs |