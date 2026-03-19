package mpc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ThresholdKeyShare represents one party's share in a t-of-n threshold scheme.
// It contains one additive sub-share for each t-element subset that includes this party.
type ThresholdKeyShare struct {
	Version        int               `json:"version"`
	PartyIndex     int               `json:"party_index"`
	NumParties     int               `json:"num_parties"`
	Threshold      int               `json:"threshold"`
	Modulus        string            `json:"modulus"`          // base64 big-endian
	PublicExponent int               `json:"public_exponent"`
	Shares         map[string]string `json:"shares"`           // subset_key -> base64 share value
}

// SplitKeyThreshold splits d into t-of-n threshold shares using redundant additive sharing.
// For each t-element subset of {1..n}, it generates an independent additive sharing of d.
func SplitKeyThreshold(d, lambda, modulus *big.Int, e, n, t int) ([]*ThresholdKeyShare, error) {
	if t < 2 || t > n {
		return nil, fmt.Errorf("threshold must be 2 <= t <= n, got t=%d n=%d", t, n)
	}
	if n < 2 {
		return nil, fmt.Errorf("need at least 2 parties")
	}

	// n-of-n is just the simple case
	if t == n {
		simple, err := SplitKey(d, lambda, modulus, e, n)
		if err != nil {
			return nil, err
		}
		// Convert to threshold format
		result := make([]*ThresholdKeyShare, n)
		subsetKey := SubsetKey(seq(1, n))
		for i, s := range simple {
			sv, _ := s.ShareValue()
			result[i] = &ThresholdKeyShare{
				Version:        2,
				PartyIndex:     i + 1,
				NumParties:     n,
				Threshold:      t,
				Modulus:        s.Modulus,
				PublicExponent: e,
				Shares: map[string]string{
					subsetKey: base64.StdEncoding.EncodeToString(sv.Bytes()),
				},
			}
		}
		return result, nil
	}

	modB64 := base64.StdEncoding.EncodeToString(modulus.Bytes())

	// Initialize per-party share maps
	result := make([]*ThresholdKeyShare, n)
	for i := 0; i < n; i++ {
		result[i] = &ThresholdKeyShare{
			Version:        2,
			PartyIndex:     i + 1,
			NumParties:     n,
			Threshold:      t,
			Modulus:        modB64,
			PublicExponent: e,
			Shares:         make(map[string]string),
		}
	}

	// Generate additive shares for each t-element subset
	subsets := combinations(n, t)
	for _, subset := range subsets {
		key := SubsetKey(subset)

		// Generate t-1 random shares, last = d - sum mod lambda
		shares := make([]*big.Int, t)
		sum := new(big.Int)
		for i := 0; i < t-1; i++ {
			share, err := rand.Int(rand.Reader, lambda)
			if err != nil {
				return nil, fmt.Errorf("generating random share: %w", err)
			}
			shares[i] = share
			sum.Add(sum, share)
		}
		shares[t-1] = new(big.Int).Sub(d, sum)
		shares[t-1].Mod(shares[t-1], lambda)

		// Assign each share to the corresponding party
		for i, partyIdx := range subset {
			result[partyIdx-1].Shares[key] = base64.StdEncoding.EncodeToString(shares[i].Bytes())
		}
	}

	return result, nil
}

// SubsetKey creates a canonical string key for a subset of party indices.
func SubsetKey(parties []int) string {
	sorted := make([]int, len(parties))
	copy(sorted, parties)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, p := range sorted {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// ParseSubsetKey parses a subset key back into party indices.
func ParseSubsetKey(key string) ([]int, error) {
	parts := strings.Split(key, ",")
	result := make([]int, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid subset key %q: %w", key, err)
		}
		result[i] = v
	}
	return result, nil
}

// FindSubset finds the subset key that matches the given set of party indices.
func FindSubset(share *ThresholdKeyShare, parties []int) (string, error) {
	key := SubsetKey(parties)
	if _, ok := share.Shares[key]; ok {
		return key, nil
	}
	return "", fmt.Errorf("no share found for subset {%s} in party %d's shares", key, share.PartyIndex)
}

// GetShareValue returns the share value for a specific subset.
func (s *ThresholdKeyShare) GetShareValue(subsetKey string) (*big.Int, error) {
	b64, ok := s.Shares[subsetKey]
	if !ok {
		return nil, fmt.Errorf("no share for subset %s", subsetKey)
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// ModulusValue decodes the modulus.
func (s *ThresholdKeyShare) ModulusValue() (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(s.Modulus)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// SaveThresholdShare writes a threshold share to a JSON file.
func SaveThresholdShare(share *ThresholdKeyShare, path string) error {
	data, err := json.MarshalIndent(share, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadThresholdShare reads a threshold share from a JSON file.
// Also handles v1 (non-threshold) shares by converting them.
func LoadThresholdShare(path string) (*ThresholdKeyShare, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Peek at version
	var peek struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return nil, err
	}

	if peek.Version == 1 {
		// Convert v1 (n-of-n) share to threshold format
		var v1 KeyShare
		if err := json.Unmarshal(data, &v1); err != nil {
			return nil, err
		}
		subsetKey := SubsetKey(seq(1, v1.NumParties))
		return &ThresholdKeyShare{
			Version:        2,
			PartyIndex:     v1.PartyIndex,
			NumParties:     v1.NumParties,
			Threshold:      v1.NumParties, // v1 is always n-of-n
			Modulus:        v1.Modulus,
			PublicExponent: v1.PublicExponent,
			Shares: map[string]string{
				subsetKey: v1.Share,
			},
		}, nil
	}

	var share ThresholdKeyShare
	if err := json.Unmarshal(data, &share); err != nil {
		return nil, err
	}
	if share.Version != 2 {
		return nil, fmt.Errorf("unsupported share version: %d", share.Version)
	}
	return &share, nil
}

// combinations generates all k-element subsets of {1..n}.
func combinations(n, k int) [][]int {
	var result [][]int
	combo := make([]int, k)
	var generate func(start, idx int)
	generate = func(start, idx int) {
		if idx == k {
			c := make([]int, k)
			copy(c, combo)
			result = append(result, c)
			return
		}
		for i := start; i <= n-(k-idx)+1; i++ {
			combo[idx] = i
			generate(i+1, idx+1)
		}
	}
	generate(1, 0)
	return result
}

func seq(from, to int) []int {
	r := make([]int, to-from+1)
	for i := range r {
		r[i] = from + i
	}
	return r
}
