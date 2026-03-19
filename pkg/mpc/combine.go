package mpc

import (
	"fmt"
	"math/big"
)

// CombinePartials multiplies all partial signatures modulo N.
// s = product(s_i) mod N = m^{sum(d_i)} mod N = m^d mod N.
func CombinePartials(partials []*PartialSignature, modulus *big.Int) ([]byte, error) {
	if len(partials) == 0 {
		return nil, fmt.Errorf("no partial signatures provided")
	}

	result := big.NewInt(1)
	for _, p := range partials {
		pv, err := p.PartialValue()
		if err != nil {
			return nil, fmt.Errorf("decoding partial %d: %w", p.PartyIndex, err)
		}
		result.Mul(result, pv)
		result.Mod(result, modulus)
	}

	// Pad to 384 bytes
	sigBytes := result.Bytes()
	padded := make([]byte, 384)
	copy(padded[384-len(sigBytes):], sigBytes)
	return padded, nil
}
