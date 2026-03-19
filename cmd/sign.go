package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/magicaltux/mpcegosign/pkg/elfutil"
	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/sgx"
)

func RunSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	configPath := fs.String("config", "enclave.json", "path to enclave.json")
	sharesStr := fs.String("shares", "", "comma-separated share files")
	output := fs.String("out", "", "output signed binary (default: overwrite exe)")
	egoPath := fs.String("ego", "", "path to EGo installation (e.g. /opt/ego)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sharesStr == "" {
		return fmt.Errorf("--shares is required")
	}

	sharePaths := strings.Split(*sharesStr, ",")
	if len(sharePaths) < 2 {
		return fmt.Errorf("need at least 2 shares")
	}

	// Load config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	exePath := cfg.Exe
	outPath := exePath
	if *output != "" {
		outPath = *output
	}

	// Copy binary if output differs
	if outPath != exePath {
		if err := elfutil.CopyFile(exePath, outPath); err != nil {
			return fmt.Errorf("copying binary: %w", err)
		}
	}

	// Load all shares
	shares := make([]*mpc.KeyShare, len(sharePaths))
	for i, p := range sharePaths {
		s, err := mpc.LoadShare(strings.TrimSpace(p))
		if err != nil {
			return fmt.Errorf("loading share %s: %w", p, err)
		}
		shares[i] = s
	}

	// Get modulus from first share
	modulus, err := shares[0].ModulusValue()
	if err != nil {
		return fmt.Errorf("decoding modulus: %w", err)
	}

	// Read .oeinfo
	oeinfo, err := elfutil.ReadOEInfo(outPath)
	if err != nil {
		return fmt.Errorf("reading .oeinfo: %w", err)
	}

	// Parse properties
	props, err := sgx.ParseEnclaveProperties(oeinfo.Data)
	if err != nil {
		return fmt.Errorf("parsing enclave properties: %w", err)
	}

	var mrenclave [32]byte
	if *egoPath != "" {
		mrenclave, err = computeMRENCLAVEWithEgo(*egoPath, outPath, *configPath)
		if err != nil {
			return fmt.Errorf("computing MRENCLAVE via ego-oesign: %w", err)
		}
	} else {
		elfInfo, err := elfutil.ReadELFInfo(outPath)
		if err != nil {
			return fmt.Errorf("reading ELF info: %w", err)
		}
		mrenclave, err = sgx.ComputeMRENCLAVE(elfInfo, props)
		if err != nil {
			return fmt.Errorf("computing MRENCLAVE: %w", err)
		}
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

	// Set misc
	ss.SetMiscSelect(0)
	ss.SetMiscMask(^uint32(0))

	// Hash for signing
	sigHash := ss.HashForSigning()
	padded := rsa3.PadPKCS1v15SHA256(sigHash)

	// Compute partial signatures
	partials := make([]*mpc.PartialSignature, len(shares))
	for i, share := range shares {
		sv, err := share.ShareValue()
		if err != nil {
			return fmt.Errorf("decoding share %d: %w", i+1, err)
		}
		partials[i] = mpc.ComputePartial(padded, sv, modulus, share.PartyIndex)
	}

	// Combine
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
	q1BE, q2BE := rsa3.ComputeQ1Q2(sigBE, modulus.Bytes())
	ss.SetQ1(rsa3.BigEndianToLittleEndian(q1BE))
	ss.SetQ2(rsa3.BigEndianToLittleEndian(q2BE))

	// Write SIGSTRUCT back
	oeinfo.SetSigStruct(ss.Bytes())
	if err := elfutil.WriteSigStructToFile(outPath, oeinfo, ss.Bytes()); err != nil {
		return fmt.Errorf("writing sigstruct: %w", err)
	}

	// Compute MRSIGNER
	mrsigner := sha256.Sum256(modLE)
	fmt.Printf("MRSIGNER:  %s\n", hex.EncodeToString(mrsigner[:]))
	fmt.Printf("Signed binary written to %s\n", outPath)

	return nil
}

func padBigIntTo(b []byte, size int) []byte {
	if len(b) >= size {
		return b[:size]
	}
	result := make([]byte, size)
	copy(result[size-len(b):], b)
	return result
}
