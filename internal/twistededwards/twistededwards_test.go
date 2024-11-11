package twistededwards

import (
	"math/big"
	"testing"
)

func TestTE2RTETransform(t *testing.T) {
	p := new(Point)
	p.X, _ = new(big.Int).SetString("20284931487578954787250358776722960153090567235942462656834196519767860852891", 10)
	p.Y, _ = new(big.Int).SetString("21185575020764391300398134415668786804224896114060668011215204645513129497221", 10)

	expectedRTE, _ := new(big.Int).SetString("5730906301301611931737915251485454905492689746504994962065413628158661689313", 10)
	pPrime := p.FromTEtoRTE()
	if pPrime.X.Cmp(expectedRTE) != 0 {
		t.Errorf("Expected %v, got %v", expectedRTE, pPrime.X)
	}
	pPrimePrime := pPrime.FromRTEtoTE()
	if pPrimePrime.X.Cmp(p.X) != 0 || pPrimePrime.Y.Cmp(p.Y) != 0 {
		t.Errorf("Expected %v, got %v", p, pPrimePrime)
	}
}
