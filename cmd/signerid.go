package cmd

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	rsa3 "github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/elfutil"
	"github.com/magicaltux/mpcegosign/pkg/sgx"
)

func RunSignerID(args []string) error {
	fs := flag.NewFlagSet("signerid", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to public key PEM")
	enclavePath := fs.String("enclave", "", "path to signed enclave binary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyPath == "" && *enclavePath == "" {
		return fmt.Errorf("--key or --enclave is required")
	}

	var modulusLE []byte

	if *keyPath != "" {
		// Load from PEM
		data, err := os.ReadFile(*keyPath)
		if err != nil {
			return fmt.Errorf("reading key: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("no PEM block found")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("not an RSA public key")
		}
		modBE := padBigIntTo(rsaPub.N.Bytes(), 384)
		modulusLE = rsa3.BigEndianToLittleEndian(modBE)
	} else {
		// Extract from binary's SIGSTRUCT
		oeinfo, err := elfutil.ReadOEInfo(*enclavePath)
		if err != nil {
			return fmt.Errorf("reading .oeinfo: %w", err)
		}
		ss, err := sgx.ParseSigStruct(oeinfo.SigStructBytes())
		if err != nil {
			return fmt.Errorf("parsing sigstruct: %w", err)
		}
		modulusLE = ss.Modulus()
	}

	mrsigner := sha256.Sum256(modulusLE)
	fmt.Println(hex.EncodeToString(mrsigner[:]))

	return nil
}
