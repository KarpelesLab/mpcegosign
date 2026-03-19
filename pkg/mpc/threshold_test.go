package mpc

import (
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/magicaltux/mpcegosign/pkg/rsa3"
)

func TestThresholdSplit2of3(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	shares, err := SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, 3, 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}

	// Each party should have C(2,1) = 2 sub-shares
	for _, s := range shares {
		if len(s.Shares) != 2 {
			t.Errorf("party %d: expected 2 sub-shares, got %d", s.PartyIndex, len(s.Shares))
		}
		if s.Threshold != 2 {
			t.Errorf("party %d: threshold=%d, want 2", s.PartyIndex, s.Threshold)
		}
	}

	// Test all 3 possible 2-party combinations
	hash := sha256.Sum256([]byte("threshold test"))
	padded := rsa3.PadPKCS1v15SHA256(hash)
	directSig := rsa3.Sign(padded, key.D, key.N)

	pairs := [][]int{{1, 2}, {1, 3}, {2, 3}}
	for _, pair := range pairs {
		subsetKey := SubsetKey(pair)
		partials := make([]*PartialSignature, 2)

		for i, partyIdx := range pair {
			share := shares[partyIdx-1]
			sv, err := share.GetShareValue(subsetKey)
			if err != nil {
				t.Fatalf("pair %v: party %d: %v", pair, partyIdx, err)
			}
			partials[i] = ComputePartialForSubset(padded, sv, key.N, partyIdx, subsetKey)
		}

		combined, err := CombinePartials(partials, key.N)
		if err != nil {
			t.Fatalf("pair %v: combine failed: %v", pair, err)
		}

		if !rsa3.Verify(combined, 3, key.N, padded) {
			t.Errorf("pair %v: signature verification failed", pair)
		}

		for i := range directSig {
			if directSig[i] != combined[i] {
				t.Errorf("pair %v: signature differs from direct at byte %d", pair, i)
				break
			}
		}
	}
}

func TestThresholdSplit4of5(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	shares, err := SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, 5, 4)
	if err != nil {
		t.Fatal(err)
	}

	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Each party should have C(4,3) = 4 sub-shares
	for _, s := range shares {
		if len(s.Shares) != 4 {
			t.Errorf("party %d: expected 4 sub-shares, got %d", s.PartyIndex, len(s.Shares))
		}
	}

	// Test a few 4-party combinations
	hash := sha256.Sum256([]byte("4of5 test"))
	padded := rsa3.PadPKCS1v15SHA256(hash)
	directSig := rsa3.Sign(padded, key.D, key.N)

	testSubsets := [][]int{
		{1, 2, 3, 4},
		{1, 2, 3, 5},
		{2, 3, 4, 5},
		{1, 3, 4, 5},
	}

	for _, subset := range testSubsets {
		subsetKey := SubsetKey(subset)
		partials := make([]*PartialSignature, 4)

		for i, partyIdx := range subset {
			share := shares[partyIdx-1]
			sv, err := share.GetShareValue(subsetKey)
			if err != nil {
				t.Fatalf("subset %v: party %d: %v", subset, partyIdx, err)
			}
			partials[i] = ComputePartialForSubset(padded, sv, key.N, partyIdx, subsetKey)
		}

		combined, err := CombinePartials(partials, key.N)
		if err != nil {
			t.Fatalf("subset %v: combine failed: %v", subset, err)
		}

		if !rsa3.Verify(combined, 3, key.N, padded) {
			t.Errorf("subset %v: signature verification failed", subset)
		}

		for i := range directSig {
			if directSig[i] != combined[i] {
				t.Errorf("subset %v: signature differs from direct at byte %d", subset, i)
				break
			}
		}
	}
}

func TestThresholdNofN(t *testing.T) {
	// n-of-n threshold should produce same result as simple split
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	shares, err := SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, 3, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Should have exactly 1 sub-share per party (the single 3-element subset)
	for _, s := range shares {
		if len(s.Shares) != 1 {
			t.Errorf("party %d: expected 1 sub-share for n-of-n, got %d", s.PartyIndex, len(s.Shares))
		}
	}

	hash := sha256.Sum256([]byte("nofn test"))
	padded := rsa3.PadPKCS1v15SHA256(hash)

	subsetKey := SubsetKey([]int{1, 2, 3})
	partials := make([]*PartialSignature, 3)
	for i := 0; i < 3; i++ {
		sv, _ := shares[i].GetShareValue(subsetKey)
		partials[i] = ComputePartialForSubset(padded, sv, key.N, i+1, subsetKey)
	}

	combined, err := CombinePartials(partials, key.N)
	if err != nil {
		t.Fatal(err)
	}

	if !rsa3.Verify(combined, 3, key.N, padded) {
		t.Error("n-of-n threshold signature verification failed")
	}
}

func TestThresholdSaveLoad(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	shares, err := SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, 3, 2)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "share.json")

	if err := SaveThresholdShare(shares[0], path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadThresholdShare(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.PartyIndex != shares[0].PartyIndex {
		t.Error("party index mismatch")
	}
	if loaded.Threshold != 2 {
		t.Errorf("threshold=%d, want 2", loaded.Threshold)
	}
	if len(loaded.Shares) != len(shares[0].Shares) {
		t.Error("sub-shares count mismatch")
	}
}

func TestThresholdV1Compat(t *testing.T) {
	// Loading a v1 share file should auto-convert to threshold format
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	v1shares, err := SplitKey(key.D, key.Lambda, key.N, key.E, 2)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "v1share.json")
	if err := SaveShare(v1shares[0], path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadThresholdShare(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Version != 2 {
		t.Errorf("version=%d, want 2", loaded.Version)
	}
	if loaded.Threshold != 2 {
		t.Errorf("threshold=%d, want 2 (n-of-n for v1)", loaded.Threshold)
	}
	if len(loaded.Shares) != 1 {
		t.Errorf("expected 1 sub-share, got %d", len(loaded.Shares))
	}
}

func TestCombinations(t *testing.T) {
	tests := []struct {
		n, k     int
		expected int
	}{
		{3, 2, 3},
		{5, 4, 5},
		{5, 3, 10},
		{5, 2, 10},
		{4, 2, 6},
		{3, 3, 1},
	}
	for _, tt := range tests {
		combos := combinations(tt.n, tt.k)
		if len(combos) != tt.expected {
			t.Errorf("C(%d,%d) = %d, want %d", tt.n, tt.k, len(combos), tt.expected)
		}
	}
}

func TestFindSubset(t *testing.T) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	shares, err := SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Party 1 should be able to find a subset with parties 2 and 4
	key1, err := FindSubset(shares[0], []int{1, 2, 4})
	if err != nil {
		t.Fatal(err)
	}
	if key1 != "1,2,4" {
		t.Errorf("expected subset key '1,2,4', got '%s'", key1)
	}

	// Party 1 should NOT have a subset that doesn't include party 1
	_, err = FindSubset(shares[0], []int{2, 3, 4})
	if err == nil {
		t.Error("expected error for subset not containing party 1")
	}
}
