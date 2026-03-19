package mpc

import (
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/magicaltux/mpcegosign/pkg/rsa3"
)

func TestSplitAndCombine(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	for _, numShares := range []int{2, 3, 5} {
		t.Run(func() string {
			return "shares_" + string(rune('0'+numShares))
		}(), func(t *testing.T) {
			shares, err := SplitKey(key.D, key.Lambda, key.N, key.E, numShares)
			if err != nil {
				t.Fatalf("SplitKey(%d) failed: %v", numShares, err)
			}

			if len(shares) != numShares {
				t.Fatalf("expected %d shares, got %d", numShares, len(shares))
			}

			// Verify shares sum to d mod lambda
			sum := new(big.Int)
			for _, s := range shares {
				sv, err := s.ShareValue()
				if err != nil {
					t.Fatal(err)
				}
				sum.Add(sum, sv)
			}
			sum.Mod(sum, key.Lambda)
			dModLambda := new(big.Int).Mod(key.D, key.Lambda)
			if sum.Cmp(dModLambda) != 0 {
				t.Error("shares don't sum to d mod lambda")
			}

			// Test MPC signing produces same result as direct signing
			hash := sha256.Sum256([]byte("test data"))
			padded := rsa3.PadPKCS1v15SHA256(hash)

			// Direct sign
			directSig := rsa3.Sign(padded, key.D, key.N)

			// MPC sign
			partials := make([]*PartialSignature, numShares)
			for i, s := range shares {
				sv, _ := s.ShareValue()
				partials[i] = ComputePartial(padded, sv, key.N, s.PartyIndex)
			}

			combined, err := CombinePartials(partials, key.N)
			if err != nil {
				t.Fatalf("CombinePartials failed: %v", err)
			}

			// Compare
			if !equal(directSig, combined) {
				t.Error("MPC signature differs from direct signature")
			}

			// Verify
			if !rsa3.Verify(combined, 3, key.N, padded) {
				t.Error("combined signature verification failed")
			}
		})
	}
}

func TestShareSaveLoad(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	shares, err := SplitKey(key.D, key.Lambda, key.N, key.E, 2)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "share.json")

	if err := SaveShare(shares[0], path); err != nil {
		t.Fatalf("SaveShare: %v", err)
	}

	loaded, err := LoadShare(path)
	if err != nil {
		t.Fatalf("LoadShare: %v", err)
	}

	if loaded.PartyIndex != shares[0].PartyIndex {
		t.Error("party index mismatch")
	}
	if loaded.NumParties != shares[0].NumParties {
		t.Error("num parties mismatch")
	}
	if loaded.Modulus != shares[0].Modulus {
		t.Error("modulus mismatch")
	}
	if loaded.Share != shares[0].Share {
		t.Error("share value mismatch")
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestPartialSaveLoad(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte("test"))
	padded := rsa3.PadPKCS1v15SHA256(hash)
	partial := ComputePartial(padded, key.D, key.N, 1)

	dir := t.TempDir()
	path := filepath.Join(dir, "partial.sig")

	if err := SavePartial(partial, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPartial(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.PartyIndex != partial.PartyIndex {
		t.Error("party index mismatch")
	}
	if loaded.PartialSignature != partial.PartialSignature {
		t.Error("partial signature mismatch")
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
