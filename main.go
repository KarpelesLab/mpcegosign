package main

import (
	"fmt"
	"os"

	"github.com/magicaltux/mpcegosign/cmd"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "keygen":
		err = cmd.RunKeygen(args)
	case "hash":
		err = cmd.RunHash(args)
	case "partial-sign":
		err = cmd.RunPartialSign(args)
	case "combine":
		err = cmd.RunCombine(args)
	case "signerid":
		err = cmd.RunSignerID(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `mpcegosign - MPC Threshold RSA Signing for EGo SGX Enclaves

Usage: mpcegosign <command> [options]

Commands:
  keygen              Interactive distributed keygen via group chat messages
                      Initiator: mpcegosign keygen --parties N --threshold T
                      Joiner:    mpcegosign keygen

  hash                Compute MRENCLAVE and output digest for distributed signing
  partial-sign        Compute partial signature with one share
  combine             Combine partial signatures into signed enclave
  signerid            Compute MRSIGNER from key or binary

Environment:
  EGO_PATH      Path to EGo installation (default: /opt/ego)
`)
}
