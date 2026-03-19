package main

import (
	"crypto/sha256"
	"testing"

	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
)

func TestEndToEndMPC(t *testing.T) {
	// Generate key
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Split into 3 shares
	shares, err := mpc.SplitKey(key.D, key.Lambda, key.N, key.E, 3)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}

	// Save and reload shares (round-trip test)
	dir := t.TempDir()
	for i, s := range shares {
		path := dir + "/share_" + string(rune('1'+i)) + ".json"
		if err := mpc.SaveShare(s, path); err != nil {
			t.Fatal(err)
		}
		loaded, err := mpc.LoadShare(path)
		if err != nil {
			t.Fatal(err)
		}
		shares[i] = loaded
	}

	// Simulate signing a SIGSTRUCT hash
	hash := sha256.Sum256([]byte("simulated sigstruct regions"))
	padded := rsa3.PadPKCS1v15SHA256(hash)

	// Direct sign for comparison
	directSig := rsa3.Sign(padded, key.D, key.N)
	if !rsa3.Verify(directSig, 3, key.N, padded) {
		t.Fatal("direct signature verification failed")
	}

	// MPC partial signatures
	modulus, _ := shares[0].ModulusValue()
	partials := make([]*mpc.PartialSignature, 3)
	for i, s := range shares {
		sv, _ := s.ShareValue()
		partials[i] = mpc.ComputePartial(padded, sv, modulus, s.PartyIndex)

		// Save and reload partial
		path := dir + "/partial_" + string(rune('1'+i)) + ".sig"
		if err := mpc.SavePartial(partials[i], path); err != nil {
			t.Fatal(err)
		}
		loaded, err := mpc.LoadPartial(path)
		if err != nil {
			t.Fatal(err)
		}
		partials[i] = loaded
	}

	// Combine
	combined, err := mpc.CombinePartials(partials, modulus)
	if err != nil {
		t.Fatalf("CombinePartials: %v", err)
	}

	// Verify combined signature
	if !rsa3.Verify(combined, 3, modulus, padded) {
		t.Fatal("combined MPC signature verification failed")
	}

	// Should match direct signature
	for i := range directSig {
		if directSig[i] != combined[i] {
			t.Fatalf("MPC signature differs from direct signature at byte %d", i)
		}
	}

	// Verify Q1/Q2 computation
	modBE := modulus.Bytes()
	q1, q2 := rsa3.ComputeQ1Q2(combined, modBE)
	if len(q1) != 384 || len(q2) != 384 {
		t.Fatalf("Q1/Q2 wrong size: %d, %d", len(q1), len(q2))
	}

	// Verify sig^3 mod N = padded_msg
	if !rsa3.Verify(combined, 3, modulus, padded) {
		t.Error("sig^3 mod N != padded_msg")
	}
}
