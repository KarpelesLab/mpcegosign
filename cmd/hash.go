package cmd

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	rsa3 "github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/config"
	"github.com/magicaltux/mpcegosign/pkg/elfutil"
	"github.com/magicaltux/mpcegosign/pkg/sgx"
)

// HashFile is the JSON structure for the hash output.
type HashFile struct {
	Version          int    `json:"version"`
	MRENCLAVE        string `json:"mrenclave"`          // hex
	PaddedDigest     string `json:"padded_digest"`      // base64, 384 bytes
	SigStructUnsigned string `json:"sigstruct_unsigned"` // base64, 1808 bytes
	ConfigHash       string `json:"config_hash"`        // hex
}

func RunHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	configPath := fs.String("config", "enclave.json", "path to enclave.json")
	pubkeyPath := fs.String("pubkey", "", "path to public key PEM")
	outPath := fs.String("out", "enclave.hash", "output hash file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *pubkeyPath == "" {
		return fmt.Errorf("--pubkey is required")
	}

	// Load config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	// Load public key
	modulus, err := loadPublicKeyModulus(*pubkeyPath)
	if err != nil {
		return fmt.Errorf("loading public key: %w", err)
	}

	exePath := cfg.Exe

	// Read .oeinfo
	oeinfo, err := elfutil.ReadOEInfo(exePath)
	if err != nil {
		return fmt.Errorf("reading .oeinfo: %w", err)
	}

	// Parse properties
	props, err := sgx.ParseEnclaveProperties(oeinfo.Data)
	if err != nil {
		return fmt.Errorf("parsing enclave properties: %w", err)
	}

	// Read ELF segments
	segments, err := elfutil.ReadLoadSegments(exePath)
	if err != nil {
		return fmt.Errorf("reading ELF segments: %w", err)
	}

	// Read relocations
	reloc, err := elfutil.ReadRelocations(exePath)
	if err != nil {
		return fmt.Errorf("reading relocations: %w", err)
	}

	// Compute MRENCLAVE
	mrenclave, err := sgx.ComputeMRENCLAVE(segments, reloc, props)
	if err != nil {
		return fmt.Errorf("computing MRENCLAVE: %w", err)
	}
	fmt.Printf("MRENCLAVE: %s\n", hex.EncodeToString(mrenclave[:]))

	// Build SIGSTRUCT
	ss := sgx.NewSigStruct()
	now := time.Now()
	ss.SetDate(now.Year(), int(now.Month()), now.Day())
	ss.SetExponent(3)

	// Set modulus (little-endian)
	modBytes := padBigIntTo(modulus.Bytes(), 384)
	modLE := rsa3.BigEndianToLittleEndian(modBytes)
	ss.SetModulus(modLE)

	// Set enclave identity
	ss.SetMRENCLAVE(mrenclave)
	ss.SetISVProdID(cfg.ProductID)
	ss.SetISVSVN(cfg.SecurityVersion)

	// Set attributes
	attrFlags := props.SGXAttributes()
	ss.SetAttributes(attrFlags, sgx.DefaultXFRM)
	ss.SetAttributesMask(props.SGXAttributesMask(), ^uint64(0))

	ss.SetMiscSelect(0)
	ss.SetMiscMask(^uint32(0))

	// Compute hash for signing
	sigHash := ss.HashForSigning()
	padded := rsa3.PadPKCS1v15SHA256(sigHash)

	// Config hash (for integrity)
	configData, _ := os.ReadFile(*configPath)
	configHash := sha256.Sum256(configData)

	// Write hash file
	hf := &HashFile{
		Version:          1,
		MRENCLAVE:        hex.EncodeToString(mrenclave[:]),
		PaddedDigest:     base64.StdEncoding.EncodeToString(padded),
		SigStructUnsigned: base64.StdEncoding.EncodeToString(ss.Bytes()),
		ConfigHash:       hex.EncodeToString(configHash[:]),
	}

	data, err := json.MarshalIndent(hf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, data, 0644); err != nil {
		return err
	}

	fmt.Printf("Hash file written to %s\n", *outPath)
	return nil
}

func loadPublicKeyModulus(path string) (*big.Int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub.N, nil
}

func loadConfig(path string) (*config.EnclaveConfig, error) {
	return config.LoadConfig(path)
}
