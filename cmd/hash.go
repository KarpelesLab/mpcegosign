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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	rsa3 "github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/config"
	"github.com/magicaltux/mpcegosign/pkg/elfutil"
	"github.com/magicaltux/mpcegosign/pkg/sgx"
)

// HashFile is the JSON structure for the hash output.
type HashFile struct {
	Version           int    `json:"version"`
	MRENCLAVE         string `json:"mrenclave"`           // hex
	PaddedDigest      string `json:"padded_digest"`       // base64, 384 bytes
	SigStructUnsigned string `json:"sigstruct_unsigned"`  // base64, 1808 bytes
	ConfigHash        string `json:"config_hash"`         // hex
}

func RunHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	configPath := fs.String("config", "enclave.json", "path to enclave.json")
	pubkeyPath := fs.String("pubkey", "", "path to public key PEM")
	outPath := fs.String("out", "enclave.hash", "output hash file")
	egoPath := fs.String("ego", "", "path to EGo installation (e.g. /opt/ego)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *pubkeyPath == "" {
		return fmt.Errorf("--pubkey is required")
	}

	// Auto-detect EGo path
	resolvedEgoPath, err := findEgoPath(*egoPath)
	if err != nil {
		return err
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

	// Compute MRENCLAVE via ego-oesign
	mrenclave, err := computeMRENCLAVEWithEgo(resolvedEgoPath, exePath, *configPath)
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

	// Read properties from binary for attributes
	oeinfo, err := elfutil.ReadOEInfo(exePath)
	if err != nil {
		return fmt.Errorf("reading .oeinfo: %w", err)
	}
	props, err := sgx.ParseEnclaveProperties(oeinfo.Data)
	if err != nil {
		return fmt.Errorf("parsing enclave properties: %w", err)
	}

	// Set attributes — match what ego-oesign uses
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
		Version:           1,
		MRENCLAVE:         hex.EncodeToString(mrenclave[:]),
		PaddedDigest:      base64.StdEncoding.EncodeToString(padded),
		SigStructUnsigned: base64.StdEncoding.EncodeToString(ss.Bytes()),
		ConfigHash:        hex.EncodeToString(configHash[:]),
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

// computeMRENCLAVEWithEgo uses ego-oesign to compute the MRENCLAVE.
// This handles the dual-image layout (ego-enclave runtime + user's Go binary).
func computeMRENCLAVEWithEgo(egoPath, payloadPath, configPath string) ([32]byte, error) {
	var mrenclave [32]byte

	oesignBin := filepath.Join(egoPath, "bin", "ego-oesign")
	enclaveImg := filepath.Join(egoPath, "share", "ego-enclave")

	// Check files exist
	for _, p := range []string{oesignBin, enclaveImg} {
		if _, err := os.Stat(p); err != nil {
			return mrenclave, fmt.Errorf("ego file not found: %s", p)
		}
	}

	// Convert enclave.json to OE config format
	oeConf, err := convertEgoConfig(configPath)
	if err != nil {
		return mrenclave, fmt.Errorf("converting config: %w", err)
	}
	defer os.Remove(oeConf)

	// Create a temporary copy of the payload for signing
	tmpPayload, err := os.CreateTemp("", "mpcegosign-payload-*")
	if err != nil {
		return mrenclave, err
	}
	tmpPayloadPath := tmpPayload.Name()
	defer os.Remove(tmpPayloadPath)

	payloadData, err := os.ReadFile(payloadPath)
	if err != nil {
		return mrenclave, err
	}
	if _, err := tmpPayload.Write(payloadData); err != nil {
		tmpPayload.Close()
		return mrenclave, err
	}
	tmpPayload.Close()

	// Create a temporary dummy key for signing (we only need the MRENCLAVE)
	tmpKey, err := createTempDummyKey()
	if err != nil {
		return mrenclave, fmt.Errorf("creating dummy key: %w", err)
	}
	defer os.Remove(tmpKey)

	// Run ego-oesign sign to compute MRENCLAVE
	cmd := exec.Command(oesignBin, "sign",
		"-e", enclaveImg,
		"--payload", tmpPayloadPath,
		"-c", oeConf,
		"-k", tmpKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return mrenclave, fmt.Errorf("ego-oesign failed: %w\n%s", err, output)
	}

	// Extract MRENCLAVE from the signed binary using dump
	cmd = exec.Command(oesignBin, "dump",
		"--enclave-image", tmpPayloadPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return mrenclave, fmt.Errorf("ego-oesign dump failed: %w\n%s", err, output)
	}

	// Parse mrenclave from output
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "mrenclave=") {
			hexStr := strings.TrimPrefix(line, "mrenclave=")
			b, err := hex.DecodeString(hexStr)
			if err != nil {
				return mrenclave, fmt.Errorf("parsing mrenclave hex: %w", err)
			}
			if len(b) != 32 {
				return mrenclave, fmt.Errorf("mrenclave wrong length: %d", len(b))
			}
			copy(mrenclave[:], b)
			return mrenclave, nil
		}
	}

	return mrenclave, fmt.Errorf("mrenclave not found in ego-oesign dump output")
}

// convertEgoConfig converts an EGo enclave.json to an OE .conf format.
func convertEgoConfig(jsonPath string) (string, error) {
	cfg, err := config.LoadConfig(jsonPath)
	if err != nil {
		return "", err
	}

	debug := 0
	if cfg.Debug {
		debug = 1
	}

	content := fmt.Sprintf("Debug=%d\nNumHeapPages=%d\nNumStackPages=1024\nNumTCS=32\nProductID=%d\nSecurityVersion=%d\n",
		debug, cfg.HeapPages(), cfg.ProductID, cfg.SecurityVersion)

	tmpFile, err := os.CreateTemp("", "mpcegosign-conf-*")
	if err != nil {
		return "", err
	}
	tmpFile.WriteString(content)
	tmpFile.Close()
	return tmpFile.Name(), nil
}

// createTempDummyKey creates a temporary RSA-3072 private key for ego-oesign.
// We need a valid key for signing, but only care about the MRENCLAVE output.
func createTempDummyKey() (string, error) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		return "", err
	}

	// Encode as PKCS#1 PEM
	privBytes := marshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}

	tmpFile, err := os.CreateTemp("", "mpcegosign-key-*")
	if err != nil {
		return "", err
	}
	pem.Encode(tmpFile, block)
	tmpFile.Close()
	return tmpFile.Name(), nil
}

// marshalPKCS1PrivateKey manually encodes an RSA private key in PKCS#1 DER format.
func marshalPKCS1PrivateKey(key *rsa3.KeyPair) []byte {
	// Use crypto/rsa types for marshaling
	stdKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: key.N,
			E: key.E,
		},
		D:      key.D,
		Primes: []*big.Int{key.P, key.Q},
	}
	stdKey.Precompute()
	return x509.MarshalPKCS1PrivateKey(stdKey)
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

func padBigIntTo(b []byte, size int) []byte {
	if len(b) >= size {
		return b[:size]
	}
	result := make([]byte, size)
	copy(result[size-len(b):], b)
	return result
}

func loadConfig(path string) (*config.EnclaveConfig, error) {
	return config.LoadConfig(path)
}

// findEgoPath resolves the EGo installation path.
// Checks --ego flag, then EGO_PATH env var, then /opt/ego.
func findEgoPath(explicit string) (string, error) {
	candidates := []string{explicit}
	if env := os.Getenv("EGO_PATH"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, "/opt/ego")

	for _, p := range candidates {
		if p == "" {
			continue
		}
		oesign := filepath.Join(p, "bin", "ego-oesign")
		if _, err := os.Stat(oesign); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("EGo installation not found; use --ego /path/to/ego or set EGO_PATH")
}
