package mpc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// KeyShare represents one party's share of the private key.
type KeyShare struct {
	Version        int    `json:"version"`
	PartyIndex     int    `json:"party_index"`
	NumParties     int    `json:"num_parties"`
	Modulus        string `json:"modulus"`          // base64 big-endian
	PublicExponent int    `json:"public_exponent"`
	Share          string `json:"share"`            // base64 big-endian
}

// SplitKey splits private exponent d into n additive shares mod lambda.
// d_1, ..., d_{n-1} are random in [0, lambda); d_n = (d - sum) mod lambda.
func SplitKey(d, lambda, modulus *big.Int, e, n int) ([]*KeyShare, error) {
	if n < 2 {
		return nil, fmt.Errorf("need at least 2 shares, got %d", n)
	}

	shares := make([]*big.Int, n)
	sum := new(big.Int)

	// Generate n-1 random shares
	for i := 0; i < n-1; i++ {
		share, err := rand.Int(rand.Reader, lambda)
		if err != nil {
			return nil, fmt.Errorf("generating random share: %w", err)
		}
		shares[i] = share
		sum.Add(sum, share)
	}

	// Last share = (d - sum) mod lambda
	shares[n-1] = new(big.Int).Sub(d, sum)
	shares[n-1].Mod(shares[n-1], lambda)

	// Encode modulus
	modB64 := base64.StdEncoding.EncodeToString(modulus.Bytes())

	result := make([]*KeyShare, n)
	for i := 0; i < n; i++ {
		result[i] = &KeyShare{
			Version:        1,
			PartyIndex:     i + 1,
			NumParties:     n,
			Modulus:        modB64,
			PublicExponent: e,
			Share:          base64.StdEncoding.EncodeToString(shares[i].Bytes()),
		}
	}

	return result, nil
}

// SaveShare writes a key share to a JSON file.
func SaveShare(share *KeyShare, path string) error {
	data, err := json.MarshalIndent(share, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadShare reads a key share from a JSON file.
func LoadShare(path string) (*KeyShare, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var share KeyShare
	if err := json.Unmarshal(data, &share); err != nil {
		return nil, err
	}
	if share.Version != 1 {
		return nil, fmt.Errorf("unsupported share version: %d", share.Version)
	}
	return &share, nil
}

// ShareValue decodes the share's big.Int value.
func (s *KeyShare) ShareValue() (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(s.Share)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// ModulusValue decodes the modulus big.Int value.
func (s *KeyShare) ModulusValue() (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(s.Modulus)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
