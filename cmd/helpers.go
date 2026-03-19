package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	rsa3 "github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/config"
)

// computeMRENCLAVEWithEgo uses ego-oesign to compute the MRENCLAVE.
func computeMRENCLAVEWithEgo(egoPath, payloadPath, configPath string) ([32]byte, error) {
	var mrenclave [32]byte

	oesignBin := filepath.Join(egoPath, "bin", "ego-oesign")
	enclaveImg := filepath.Join(egoPath, "share", "ego-enclave")

	for _, p := range []string{oesignBin, enclaveImg} {
		if _, err := os.Stat(p); err != nil {
			return mrenclave, fmt.Errorf("ego file not found: %s", p)
		}
	}

	oeConf, err := convertEgoConfig(configPath)
	if err != nil {
		return mrenclave, fmt.Errorf("converting config: %w", err)
	}
	defer os.Remove(oeConf)

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
	tmpPayload.Write(payloadData)
	tmpPayload.Close()

	tmpKey, err := createTempDummyKey()
	if err != nil {
		return mrenclave, fmt.Errorf("creating dummy key: %w", err)
	}
	defer os.Remove(tmpKey)

	cmd := exec.Command(oesignBin, "sign",
		"-e", enclaveImg,
		"--payload", tmpPayloadPath,
		"-c", oeConf,
		"-k", tmpKey)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return mrenclave, fmt.Errorf("ego-oesign failed: %w\n%s", err, output)
	}

	cmd = exec.Command(oesignBin, "dump",
		"--enclave-image", tmpPayloadPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return mrenclave, fmt.Errorf("ego-oesign dump failed: %w\n%s", err, output)
	}

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

func createTempDummyKey() (string, error) {
	key, err := rsa3.GenerateKey()
	if err != nil {
		return "", err
	}

	privBytes := marshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}

	tmpFile, err := os.CreateTemp("", "mpcegosign-key-*")
	if err != nil {
		return "", err
	}
	pem.Encode(tmpFile, block)
	tmpFile.Close()
	return tmpFile.Name(), nil
}

func marshalPKCS1PrivateKey(key *rsa3.KeyPair) []byte {
	stdKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: key.N, E: key.E},
		D:         key.D,
		Primes:    []*big.Int{key.P, key.Q},
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
