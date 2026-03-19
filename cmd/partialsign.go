package cmd

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/magicaltux/mpcegosign/pkg/mpc"
)

func RunPartialSign(args []string) error {
	fs := flag.NewFlagSet("partial-sign", flag.ExitOnError)
	sharePath := fs.String("share", "", "path to key share JSON")
	hashPath := fs.String("hash", "", "path to hash file")
	outPath := fs.String("out", "partial.sig", "output partial signature file")
	subsetStr := fs.String("subset", "", "subset to sign for (e.g. '1,2,4'); auto-detected if omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sharePath == "" || *hashPath == "" {
		return fmt.Errorf("--share and --hash are required")
	}

	// Load share (supports both v1 and v2)
	share, err := mpc.LoadThresholdShare(*sharePath)
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

	modulus, err := share.ModulusValue()
	if err != nil {
		return fmt.Errorf("decoding modulus: %w", err)
	}

	// Determine which subset to use
	var subsetKey string
	if *subsetStr != "" {
		// Parse explicit subset
		parts := strings.Split(*subsetStr, ",")
		indices := make([]int, len(parts))
		for i, p := range parts {
			fmt.Sscanf(strings.TrimSpace(p), "%d", &indices[i])
		}
		subsetKey = mpc.SubsetKey(indices)
	} else if len(share.Shares) == 1 {
		// Only one subset (n-of-n), use it
		for k := range share.Shares {
			subsetKey = k
		}
	} else {
		// List available subsets and ask user to specify
		fmt.Fprintf(os.Stderr, "This share has %d sub-shares for different subsets.\n", len(share.Shares))
		fmt.Fprintf(os.Stderr, "Available subsets:\n")
		for k := range share.Shares {
			fmt.Fprintf(os.Stderr, "  %s\n", k)
		}
		return fmt.Errorf("--subset is required for threshold shares (e.g. --subset 1,2,4)")
	}

	shareVal, err := share.GetShareValue(subsetKey)
	if err != nil {
		return fmt.Errorf("getting share for subset %s: %w", subsetKey, err)
	}

	// Compute partial signature
	partial := mpc.ComputePartialForSubset(padded, shareVal, modulus, share.PartyIndex, subsetKey)

	if err := mpc.SavePartial(partial, *outPath); err != nil {
		return fmt.Errorf("saving partial signature: %w", err)
	}

	fmt.Printf("Partial signature (party %d, subset {%s}) written to %s\n", share.PartyIndex, subsetKey, *outPath)
	return nil
}
