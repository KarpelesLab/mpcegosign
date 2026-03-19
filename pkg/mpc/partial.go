package mpc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// PartialSignature represents one party's partial signature.
type PartialSignature struct {
	Version          int    `json:"version"`
	PartyIndex       int    `json:"party_index"`
	SubsetKey        string `json:"subset_key,omitempty"` // which subset this partial is for
	PartialSignature string `json:"partial_signature"`    // base64 big-endian
}

// ComputePartial computes s_i = padded_msg^{d_i} mod N.
func ComputePartial(paddedMsg []byte, shareValue, modulus *big.Int, partyIndex int) *PartialSignature {
	m := new(big.Int).SetBytes(paddedMsg)
	si := new(big.Int).Exp(m, shareValue, modulus)

	return &PartialSignature{
		Version:          1,
		PartyIndex:       partyIndex,
		PartialSignature: base64.StdEncoding.EncodeToString(si.Bytes()),
	}
}

// ComputePartialForSubset computes a partial signature for a specific subset.
func ComputePartialForSubset(paddedMsg []byte, shareValue, modulus *big.Int, partyIndex int, subsetKey string) *PartialSignature {
	m := new(big.Int).SetBytes(paddedMsg)
	si := new(big.Int).Exp(m, shareValue, modulus)

	return &PartialSignature{
		Version:          1,
		PartyIndex:       partyIndex,
		SubsetKey:        subsetKey,
		PartialSignature: base64.StdEncoding.EncodeToString(si.Bytes()),
	}
}

// SavePartial writes a partial signature to a JSON file.
func SavePartial(ps *PartialSignature, path string) error {
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadPartial reads a partial signature from a JSON file.
func LoadPartial(path string) (*PartialSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ps PartialSignature
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, err
	}
	if ps.Version != 1 {
		return nil, fmt.Errorf("unsupported partial signature version: %d", ps.Version)
	}
	return &ps, nil
}

// PartialValue decodes the partial signature's big.Int value.
func (p *PartialSignature) PartialValue() (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(p.PartialSignature)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
