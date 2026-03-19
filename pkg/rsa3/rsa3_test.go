package rsa3

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key.N.BitLen() != 3072 {
		t.Errorf("expected 3072-bit modulus, got %d", key.N.BitLen())
	}

	if key.E != 3 {
		t.Errorf("expected e=3, got %d", key.E)
	}

	// Verify d*e ≡ 1 (mod lambda)
	de := new(big.Int).Mul(key.D, big.NewInt(3))
	de.Mod(de, key.Lambda)
	if de.Cmp(big.NewInt(1)) != 0 {
		t.Error("d*e != 1 mod lambda")
	}

	// Verify p mod 3 != 1 and q mod 3 != 1
	three := big.NewInt(3)
	one := big.NewInt(1)
	if new(big.Int).Mod(key.P, three).Cmp(one) == 0 {
		t.Error("p mod 3 == 1")
	}
	if new(big.Int).Mod(key.Q, three).Cmp(one) == 0 {
		t.Error("q mod 3 == 1")
	}
}

func TestSignVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	hash := sha256.Sum256([]byte("test message"))
	padded := PadPKCS1v15SHA256(hash)

	sig := Sign(padded, key.D, key.N)

	if !Verify(sig, key.E, key.N, padded) {
		t.Error("signature verification failed")
	}

	// Tamper and verify failure
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	if Verify(tampered, key.E, key.N, padded) {
		t.Error("tampered signature should not verify")
	}
}

func TestPadPKCS1v15SHA256(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	padded := PadPKCS1v15SHA256(hash)

	if len(padded) != 384 {
		t.Fatalf("expected 384 bytes, got %d", len(padded))
	}

	if padded[0] != 0x00 || padded[1] != 0x01 {
		t.Error("invalid padding header")
	}

	// Check FF padding
	for i := 2; i < 332; i++ {
		if padded[i] != 0xFF {
			t.Errorf("expected 0xFF at position %d, got %02x", i, padded[i])
		}
	}

	if padded[332] != 0x00 {
		t.Error("missing separator byte")
	}

	// DigestInfo prefix starts at 333
	expectedPrefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	for i, b := range expectedPrefix {
		if padded[333+i] != b {
			t.Errorf("DigestInfo mismatch at %d: got %02x, want %02x", i, padded[333+i], b)
		}
	}
}

func TestQ1Q2(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	hash := sha256.Sum256([]byte("test"))
	padded := PadPKCS1v15SHA256(hash)
	sig := Sign(padded, key.D, key.N)

	q1BE, q2BE := ComputeQ1Q2(sig, key.N.Bytes())

	// Verify: sig^2 = q1*N + R, sig*R = q2*N + ...
	sigInt := new(big.Int).SetBytes(sig)
	nInt := key.N
	q1Int := new(big.Int).SetBytes(q1BE)
	q2Int := new(big.Int).SetBytes(q2BE)

	// sig^2 mod N = R
	sig2 := new(big.Int).Mul(sigInt, sigInt)
	q1TimesN := new(big.Int).Mul(q1Int, nInt)
	r := new(big.Int).Sub(sig2, q1TimesN)

	if r.Sign() < 0 || r.Cmp(nInt) >= 0 {
		t.Error("Q1 computation error: R out of range")
	}

	// sig*R = q2*N + remainder
	sigR := new(big.Int).Mul(sigInt, r)
	q2TimesN := new(big.Int).Mul(q2Int, nInt)
	remainder := new(big.Int).Sub(sigR, q2TimesN)

	if remainder.Sign() < 0 || remainder.Cmp(nInt) >= 0 {
		t.Error("Q2 computation error: remainder out of range")
	}
}

func TestSignSigStruct(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	hash := sha256.Sum256([]byte("sigstruct data"))
	sig, err := SignSigStruct(hash, key.D, key.N)
	if err != nil {
		t.Fatalf("SignSigStruct failed: %v", err)
	}

	padded := PadPKCS1v15SHA256(hash)
	if !Verify(sig, key.E, key.N, padded) {
		t.Error("SignSigStruct output doesn't verify")
	}
}
