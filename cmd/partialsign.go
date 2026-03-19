package cmd

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/magicaltux/mpcegosign/pkg/mpc"
)

func RunPartialSign(args []string) error {
	fs := flag.NewFlagSet("partial-sign", flag.ExitOnError)
	sharePath := fs.String("share", "", "path to key share JSON")
	hashPath := fs.String("hash", "", "path to hash file")
	outPath := fs.String("out", "partial.sig", "output partial signature file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sharePath == "" || *hashPath == "" {
		return fmt.Errorf("--share and --hash are required")
	}

	// Load share
	share, err := mpc.LoadShare(*sharePath)
	if err != nil {
		return fmt.Errorf("loading share: %w", err)
	}

	// Load hash file
	hashData, err := os.ReadFile(*hashPath)
	if err != nil {
		return fmt.Errorf("reading hash file: %w", err)
	}
	var hf HashFile
	if err := json.Unmarshal(hashData, &hf); err != nil {
		return fmt.Errorf("parsing hash file: %w", err)
	}

	// Decode padded digest
	padded, err := base64.StdEncoding.DecodeString(hf.PaddedDigest)
	if err != nil {
		return fmt.Errorf("decoding padded digest: %w", err)
	}

	// Get share and modulus values
	shareVal, err := share.ShareValue()
	if err != nil {
		return fmt.Errorf("decoding share value: %w", err)
	}
	modulus, err := share.ModulusValue()
	if err != nil {
		return fmt.Errorf("decoding modulus: %w", err)
	}

	// Compute partial signature
	partial := mpc.ComputePartial(padded, shareVal, modulus, share.PartyIndex)

	// Save
	if err := mpc.SavePartial(partial, *outPath); err != nil {
		return fmt.Errorf("saving partial signature: %w", err)
	}

	fmt.Printf("Partial signature (party %d) written to %s\n", share.PartyIndex, *outPath)
	return nil
}
