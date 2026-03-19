package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
)

func RunKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	shares := fs.Int("shares", 2, "number of key shares (n-of-n)")
	outDir := fs.String("out-dir", ".", "output directory for shares and public key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *shares < 2 {
		return fmt.Errorf("need at least 2 shares")
	}

	fmt.Println("Generating RSA-3072 key with e=3...")
	key, err := rsa3.GenerateKey()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	fmt.Printf("Key generated: %d-bit modulus\n", key.N.BitLen())

	// Create output directory
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Save public key as PEM
	pubKeyPath := filepath.Join(*outDir, "public.pem")
	if err := savePublicKeyPEM(pubKeyPath, key); err != nil {
		return fmt.Errorf("saving public key: %w", err)
	}
	fmt.Printf("Public key saved to %s\n", pubKeyPath)

	// Split key into shares
	fmt.Printf("Splitting key into %d shares...\n", *shares)
	keyShares, err := mpc.SplitKey(key.D, key.Lambda, key.N, key.E, *shares)
	if err != nil {
		return fmt.Errorf("splitting key: %w", err)
	}

	for i, share := range keyShares {
		sharePath := filepath.Join(*outDir, fmt.Sprintf("share_%d.json", i+1))
		if err := mpc.SaveShare(share, sharePath); err != nil {
			return fmt.Errorf("saving share %d: %w", i+1, err)
		}
		fmt.Printf("Share %d saved to %s\n", i+1, sharePath)
	}

	fmt.Println("Done. Keep shares secure and distribute to separate parties.")
	return nil
}

func savePublicKeyPEM(path string, key *rsa3.KeyPair) error {
	pubKey := &rsa.PublicKey{N: key.N, E: key.E}
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}
