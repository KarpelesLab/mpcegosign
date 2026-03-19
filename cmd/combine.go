package cmd

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/magicaltux/mpcegosign/pkg/elfutil"
	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/sgx"
)

func RunCombine(args []string) error {
	fs := flag.NewFlagSet("combine", flag.ExitOnError)
	partialsStr := fs.String("partials", "", "comma-separated partial signature files")
	hashPath := fs.String("hash", "", "path to hash file")
	enclavePath := fs.String("enclave", "", "path to unsigned enclave binary")
	outPath := fs.String("out", "", "output signed binary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *partialsStr == "" || *hashPath == "" || *enclavePath == "" {
		return fmt.Errorf("--partials, --hash, and --enclave are required")
	}
	if *outPath == "" {
		*outPath = *enclavePath + ".signed"
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

	// Decode padded digest and sigstruct
	padded, err := base64.StdEncoding.DecodeString(hf.PaddedDigest)
	if err != nil {
		return fmt.Errorf("decoding padded digest: %w", err)
	}
	sigstructBytes, err := base64.StdEncoding.DecodeString(hf.SigStructUnsigned)
	if err != nil {
		return fmt.Errorf("decoding sigstruct: %w", err)
	}

	// Parse sigstruct
	ss, err := sgx.ParseSigStruct(sigstructBytes)
	if err != nil {
		return fmt.Errorf("parsing sigstruct: %w", err)
	}

	// Load partial signatures
	partialPaths := strings.Split(*partialsStr, ",")
	partials := make([]*mpc.PartialSignature, len(partialPaths))
	for i, p := range partialPaths {
		ps, err := mpc.LoadPartial(strings.TrimSpace(p))
		if err != nil {
			return fmt.Errorf("loading partial %s: %w", p, err)
		}
		partials[i] = ps
	}

	// Verify all partials are for the same subset (if threshold)
	if partials[0].SubsetKey != "" {
		for i := 1; i < len(partials); i++ {
			if partials[i].SubsetKey != partials[0].SubsetKey {
				return fmt.Errorf("partial signatures are for different subsets: %s vs %s",
					partials[0].SubsetKey, partials[i].SubsetKey)
			}
		}
		fmt.Printf("Combining partials for subset {%s}\n", partials[0].SubsetKey)
	}

	// Get modulus from sigstruct (stored little-endian)
	modLE := ss.Modulus()
	modBE := rsa3.LittleEndianToBigEndian(modLE)
	modulus := new(big.Int).SetBytes(modBE)

	// Combine partial signatures
	sigBE, err := mpc.CombinePartials(partials, modulus)
	if err != nil {
		return fmt.Errorf("combining signatures: %w", err)
	}

	// Verify
	if !rsa3.Verify(sigBE, 3, modulus, padded) {
		return fmt.Errorf("combined signature verification failed")
	}
	fmt.Println("Signature verified successfully")

	// Set signature (little-endian)
	sigLE := rsa3.BigEndianToLittleEndian(sigBE)
	ss.SetSignature(sigLE)

	// Compute Q1/Q2
	q1BE, q2BE := rsa3.ComputeQ1Q2(sigBE, modBE)
	ss.SetQ1(rsa3.BigEndianToLittleEndian(q1BE))
	ss.SetQ2(rsa3.BigEndianToLittleEndian(q2BE))

	// Copy binary
	if err := elfutil.CopyFile(*enclavePath, *outPath); err != nil {
		return fmt.Errorf("copying binary: %w", err)
	}

	// Read .oeinfo from the copy
	oeinfo, err := elfutil.ReadOEInfo(*outPath)
	if err != nil {
		return fmt.Errorf("reading .oeinfo: %w", err)
	}

	// Write sigstruct
	if err := elfutil.WriteSigStructToFile(*outPath, oeinfo, ss.Bytes()); err != nil {
		return fmt.Errorf("writing sigstruct: %w", err)
	}

	fmt.Printf("Signed binary written to %s\n", *outPath)
	return nil
}
