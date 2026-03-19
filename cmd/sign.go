package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/magicaltux/mpcegosign/pkg/elfutil"
	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
	"github.com/magicaltux/mpcegosign/pkg/sgx"
)

const (
	msgTypeSignInit    = "sign-init"
	msgTypeSignPartial = "sign-partial"
)

type signInitMessage struct {
	Type              string `json:"type"`
	SessionID         string `json:"session_id"`
	MRENCLAVE         string `json:"mrenclave"`
	PaddedDigest      string `json:"padded_digest"`       // base64
	SigStructUnsigned string `json:"sigstruct_unsigned"`   // base64
	InitiatorParty    int    `json:"initiator_party"`
	Threshold         int    `json:"threshold"`
	NumParties        int    `json:"num_parties"`
}

type signPartialMessage struct {
	Type       string            `json:"type"`
	SessionID  string            `json:"session_id"`
	PartyIndex int               `json:"party_index"`
	MRENCLAVE  string            `json:"mrenclave"` // for verification
	Partials   map[string]string `json:"partials"`  // subset_key -> base64 partial sig
}

func RunSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	configPath := fs.String("config", "", "path to enclave.json (initiator only)")
	sharePath := fs.String("share", "", "path to key share JSON")
	outPath := fs.String("out", "", "output signed binary (initiator only)")
	egoPath := fs.String("ego", "", "path to EGo installation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sharePath == "" {
		return fmt.Errorf("--share is required")
	}

	share, err := mpc.LoadThresholdShare(*sharePath)
	if err != nil {
		return fmt.Errorf("loading share: %w", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	if *configPath != "" {
		return runSignInitiator(scanner, share, *configPath, *outPath, *egoPath)
	}
	return runSignSigner(scanner, share)
}

func runSignInitiator(scanner *bufio.Scanner, share *mpc.ThresholdKeyShare, configPath, outPath, egoPath string) error {
	// Resolve EGo
	resolvedEgoPath, err := findEgoPath(egoPath)
	if err != nil {
		return err
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	exePath := cfg.Exe
	if outPath == "" {
		outPath = exePath + ".signed"
	}

	log("Computing MRENCLAVE via ego-oesign...")
	mrenclave, err := computeMRENCLAVEWithEgo(resolvedEgoPath, exePath, configPath)
	if err != nil {
		return fmt.Errorf("computing MRENCLAVE: %w", err)
	}
	mrenclaveHex := hex.EncodeToString(mrenclave[:])
	log("MRENCLAVE: %s", mrenclaveHex)

	// Build SIGSTRUCT
	modulus, err := share.ModulusValue()
	if err != nil {
		return err
	}

	ss := sgx.NewSigStruct()
	now := time.Now()
	ss.SetDate(now.Year(), int(now.Month()), now.Day())
	ss.SetExponent(3)

	modBytes := padBigIntTo(modulus.Bytes(), 384)
	modLE := rsa3.BigEndianToLittleEndian(modBytes)
	ss.SetModulus(modLE)
	ss.SetMRENCLAVE(mrenclave)
	ss.SetISVProdID(cfg.ProductID)
	ss.SetISVSVN(cfg.SecurityVersion)

	oeinfo, err := elfutil.ReadOEInfo(exePath)
	if err != nil {
		return err
	}
	props, err := sgx.ParseEnclaveProperties(oeinfo.Data)
	if err != nil {
		return err
	}
	ss.SetAttributes(props.SGXAttributes(), sgx.DefaultXFRM)
	ss.SetAttributesMask(props.SGXAttributesMask(), ^uint64(0))
	ss.SetMiscSelect(0)
	ss.SetMiscMask(^uint32(0))

	sigHash := ss.HashForSigning()
	padded := rsa3.PadPKCS1v15SHA256(sigHash)

	// Generate session ID
	sessionBytes := make([]byte, 16)
	cryptoRandRead(sessionBytes)
	sessionID := base64.RawURLEncoding.EncodeToString(sessionBytes)

	// Post SIGN-INIT
	initMsg := &signInitMessage{
		Type:              msgTypeSignInit,
		SessionID:         sessionID,
		MRENCLAVE:         mrenclaveHex,
		PaddedDigest:      base64.StdEncoding.EncodeToString(padded),
		SigStructUnsigned: base64.StdEncoding.EncodeToString(ss.Bytes()),
		InitiatorParty:    share.PartyIndex,
		Threshold:         share.Threshold,
		NumParties:        share.NumParties,
	}
	sendMsg("SIGN-INIT", encodeMsg(initMsg))

	// Compute our own partials for all subsets we belong to
	myPartials := computeAllPartials(share, padded, modulus)
	log("Computed %d partial signatures for our subsets", len(myPartials))

	// Collect partials from others
	// We need threshold-1 other parties
	needed := share.Threshold - 1
	log("Waiting for %d other partial signatures...", needed)

	// Track all received partials: party_index -> {subset_key -> partial_value}
	allPartials := make(map[int]map[string]*big.Int)
	allPartials[share.PartyIndex] = myPartials

	for len(allPartials)-1 < needed {
		prompt("Paste a message from the group (%d/%d received):", len(allPartials)-1, needed)
		if !scanner.Scan() {
			return fmt.Errorf("unexpected end of input")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var partial signPartialMessage
		if err := decodeMsg(line, &partial); err != nil {
			log("(not a valid message, ignoring)")
			continue
		}
		if partial.Type != msgTypeSignPartial {
			log("(ignoring %s message)", partial.Type)
			continue
		}
		if partial.SessionID != sessionID {
			log("(ignoring message from different session)")
			continue
		}
		if partial.MRENCLAVE != mrenclaveHex {
			log("WARNING: party %d has different MRENCLAVE! Theirs: %s", partial.PartyIndex, partial.MRENCLAVE)
			continue
		}

		// Decode partials
		partyPartials := make(map[string]*big.Int)
		for subsetKey, b64 := range partial.Partials {
			b, _ := base64.StdEncoding.DecodeString(b64)
			partyPartials[subsetKey] = new(big.Int).SetBytes(b)
		}
		allPartials[partial.PartyIndex] = partyPartials
		log("Party %d signed (%d/%d)", partial.PartyIndex, len(allPartials)-1, needed)
	}

	// Find a valid subset
	parties := make([]int, 0, len(allPartials))
	for p := range allPartials {
		parties = append(parties, p)
	}

	subsetKey, err := findValidSubset(parties, share.Threshold)
	if err != nil {
		return fmt.Errorf("cannot find valid subset: %w", err)
	}
	log("Using subset {%s}", subsetKey)

	// Build combined signature
	subsetParties, _ := mpc.ParseSubsetKey(subsetKey)
	combinedPartials := make([]*mpc.PartialSignature, len(subsetParties))
	for i, p := range subsetParties {
		pv, ok := allPartials[p][subsetKey]
		if !ok {
			return fmt.Errorf("party %d missing partial for subset {%s}", p, subsetKey)
		}
		combinedPartials[i] = &mpc.PartialSignature{
			PartyIndex:       p,
			SubsetKey:        subsetKey,
			PartialSignature: base64.StdEncoding.EncodeToString(pv.Bytes()),
		}
	}

	sigBE, err := mpc.CombinePartials(combinedPartials, modulus)
	if err != nil {
		return fmt.Errorf("combining: %w", err)
	}

	if !rsa3.Verify(sigBE, 3, modulus, padded) {
		return fmt.Errorf("combined signature verification failed")
	}
	log("Signature verified!")

	// Write signed binary
	sigLE := rsa3.BigEndianToLittleEndian(sigBE)
	ss.SetSignature(sigLE)

	q1BE, q2BE := rsa3.ComputeQ1Q2(sigBE, modulus.Bytes())
	ss.SetQ1(rsa3.BigEndianToLittleEndian(q1BE))
	ss.SetQ2(rsa3.BigEndianToLittleEndian(q2BE))

	if err := elfutil.CopyFile(exePath, outPath); err != nil {
		return err
	}
	outOeinfo, err := elfutil.ReadOEInfo(outPath)
	if err != nil {
		return err
	}
	if err := elfutil.WriteSigStructToFile(outPath, outOeinfo, ss.Bytes()); err != nil {
		return err
	}

	mrsigner := sha256.Sum256(modLE)
	log("MRSIGNER:  %s", hex.EncodeToString(mrsigner[:]))
	log("Signed binary written to %s", outPath)

	return nil
}

func runSignSigner(scanner *bufio.Scanner, share *mpc.ThresholdKeyShare) error {
	log("Ready to sign (party %d, %d-of-%d)", share.PartyIndex, share.Threshold, share.NumParties)
	prompt("Paste the sign-init message from the group:")

	// Wait for SIGN-INIT
	var init signInitMessage
	for {
		if !scanner.Scan() {
			return fmt.Errorf("unexpected end of input")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := decodeMsg(line, &init); err != nil {
			log("(not a valid message, try again)")
			continue
		}
		if init.Type != msgTypeSignInit {
			log("(not a sign-init message, waiting...)")
			continue
		}
		break
	}

	log("MRENCLAVE: %s", init.MRENCLAVE)
	log("Initiator: party %d, %d-of-%d threshold", init.InitiatorParty, init.Threshold, init.NumParties)

	// Decode padded digest
	padded, err := base64.StdEncoding.DecodeString(init.PaddedDigest)
	if err != nil {
		return fmt.Errorf("decoding digest: %w", err)
	}

	modulus, err := share.ModulusValue()
	if err != nil {
		return err
	}

	// Compute partials for all subsets containing both us and the initiator
	myPartials := computePartialsWithPeer(share, padded, modulus, init.InitiatorParty)
	if len(myPartials) == 0 {
		return fmt.Errorf("no valid subsets found containing both party %d and party %d", share.PartyIndex, init.InitiatorParty)
	}

	// Encode and output
	encodedPartials := make(map[string]string)
	for k, v := range myPartials {
		encodedPartials[k] = base64.StdEncoding.EncodeToString(v.Bytes())
	}

	partialMsg := &signPartialMessage{
		Type:       msgTypeSignPartial,
		SessionID:  init.SessionID,
		PartyIndex: share.PartyIndex,
		MRENCLAVE:  init.MRENCLAVE,
		Partials:   encodedPartials,
	}

	sendMsg("SIGN-PARTIAL", encodeMsg(partialMsg))
	log("Done! Partial signature sent (%d subsets covered)", len(myPartials))

	return nil
}

// computeAllPartials computes partial signatures for ALL subsets this party belongs to.
func computeAllPartials(share *mpc.ThresholdKeyShare, padded []byte, modulus *big.Int) map[string]*big.Int {
	m := new(big.Int).SetBytes(padded)
	result := make(map[string]*big.Int)
	for subsetKey := range share.Shares {
		sv, err := share.GetShareValue(subsetKey)
		if err != nil {
			continue
		}
		result[subsetKey] = new(big.Int).Exp(m, sv, modulus)
	}
	return result
}

// computePartialsWithPeer computes partial signatures only for subsets containing
// both this party and the given peer party.
func computePartialsWithPeer(share *mpc.ThresholdKeyShare, padded []byte, modulus *big.Int, peerParty int) map[string]*big.Int {
	m := new(big.Int).SetBytes(padded)
	result := make(map[string]*big.Int)
	for subsetKey := range share.Shares {
		parties, err := mpc.ParseSubsetKey(subsetKey)
		if err != nil {
			continue
		}
		// Check if peer is in this subset
		hasPeer := false
		for _, p := range parties {
			if p == peerParty {
				hasPeer = true
				break
			}
		}
		if !hasPeer {
			continue
		}
		sv, err := share.GetShareValue(subsetKey)
		if err != nil {
			continue
		}
		result[subsetKey] = new(big.Int).Exp(m, sv, modulus)
	}
	return result
}

// findValidSubset finds a subset key that all given parties belong to.
func findValidSubset(parties []int, threshold int) (string, error) {
	if len(parties) < threshold {
		return "", fmt.Errorf("only %d parties, need %d", len(parties), threshold)
	}

	// Try all threshold-sized subsets of the given parties
	subsets := combinationsOf(parties, threshold)
	for _, subset := range subsets {
		return mpc.SubsetKey(subset), nil
	}
	return "", fmt.Errorf("no valid subset found")
}

// combinationsOf generates all k-element subsets of the given slice.
func combinationsOf(items []int, k int) [][]int {
	var result [][]int
	combo := make([]int, k)
	var gen func(start, idx int)
	gen = func(start, idx int) {
		if idx == k {
			c := make([]int, k)
			copy(c, combo)
			result = append(result, c)
			return
		}
		for i := start; i < len(items); i++ {
			combo[idx] = items[i]
			gen(i+1, idx+1)
		}
	}
	gen(0, 0)
	return result
}

func cryptoRandRead(b []byte) {
	rand.Read(b)
}
