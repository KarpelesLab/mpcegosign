package rsa3

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// KeyPair holds an RSA-3072 key with e=3.
type KeyPair struct {
	N      *big.Int // modulus
	E      int      // public exponent (always 3)
	D      *big.Int // private exponent
	P      *big.Int // prime factor
	Q      *big.Int // prime factor
	Lambda *big.Int // lcm(p-1, q-1)
}

// GenerateKey generates an RSA-3072 key pair with e=3.
// Primes p and q are chosen such that p mod 3 != 1 and q mod 3 != 1,
// ensuring that 3 is coprime to (p-1) and (q-1).
func GenerateKey() (*KeyPair, error) {
	three := big.NewInt(3)
	one := big.NewInt(1)

	for attempts := 0; attempts < 1000; attempts++ {
		p, err := generatePrimeE3(1536)
		if err != nil {
			return nil, err
		}
		q, err := generatePrimeE3(1536)
		if err != nil {
			return nil, err
		}

		// Ensure p != q
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)

		// Verify N is 3072 bits
		if n.BitLen() != 3072 {
			continue
		}

		// lambda = lcm(p-1, q-1)
		p1 := new(big.Int).Sub(p, one)
		q1 := new(big.Int).Sub(q, one)
		lambda := lcm(p1, q1)

		// d = modInverse(3, lambda)
		d := new(big.Int).ModInverse(three, lambda)
		if d == nil {
			continue // gcd(3, lambda) != 1, shouldn't happen with our prime selection
		}

		return &KeyPair{
			N:      n,
			E:      3,
			D:      d,
			P:      p,
			Q:      q,
			Lambda: lambda,
		}, nil
	}

	return nil, errors.New("failed to generate RSA-3072/e=3 key after 1000 attempts")
}

// generatePrimeE3 generates a prime p of the given bit size where p mod 3 != 1
// (equivalently, p mod 3 == 2), so that gcd(3, p-1) = 1.
func generatePrimeE3(bits int) (*big.Int, error) {
	three := big.NewInt(3)
	one := big.NewInt(1)
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		// p mod 3 must not be 1
		rem := new(big.Int).Mod(p, three)
		if rem.Cmp(one) != 0 {
			return p, nil
		}
	}
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	// lcm = |a*b| / gcd(a,b)
	ab := new(big.Int).Mul(a, b)
	ab.Abs(ab)
	return ab.Div(ab, g)
}
