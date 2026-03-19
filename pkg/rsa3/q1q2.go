package rsa3

import "math/big"

// ComputeQ1Q2 computes Q1 and Q2 for a SIGSTRUCT given the signature and modulus.
// Both inputs and outputs are big-endian big integers.
//
// Q1 = floor(sig^2 / mod)
// R  = sig^2 mod mod
// Q2 = floor(sig * R / mod)
func ComputeQ1Q2(sigBE, modBE []byte) (q1BE, q2BE []byte) {
	sig := new(big.Int).SetBytes(sigBE)
	mod := new(big.Int).SetBytes(modBE)

	// sig^2
	sig2 := new(big.Int).Mul(sig, sig)

	// Q1 = floor(sig^2 / mod)
	q1 := new(big.Int).Div(sig2, mod)

	// R = sig^2 mod mod
	r := new(big.Int).Mod(sig2, mod)

	// sig * R
	sigR := new(big.Int).Mul(sig, r)

	// Q2 = floor(sig * R / mod)
	q2 := new(big.Int).Div(sigR, mod)

	// Pad to 384 bytes big-endian
	q1Bytes := padTo(q1.Bytes(), 384)
	q2Bytes := padTo(q2.Bytes(), 384)

	return q1Bytes, q2Bytes
}

func padTo(b []byte, size int) []byte {
	if len(b) >= size {
		return b[:size]
	}
	result := make([]byte, size)
	copy(result[size-len(b):], b)
	return result
}

// BigEndianToLittleEndian reverses a byte slice (returns a new slice).
func BigEndianToLittleEndian(be []byte) []byte {
	le := make([]byte, len(be))
	for i, b := range be {
		le[len(be)-1-i] = b
	}
	return le
}

// LittleEndianToBigEndian reverses a byte slice (returns a new slice).
func LittleEndianToBigEndian(le []byte) []byte {
	return BigEndianToLittleEndian(le) // same operation
}
