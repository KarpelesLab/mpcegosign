package cmd

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
)

// ANSI colors for terminal output
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// Protocol message types
const (
	msgTypeInit     = "keygen-init"
	msgTypeJoin     = "keygen-join"
	msgTypeFinalize = "keygen-finalize"
)

type initMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Parties   int    `json:"parties"`
	Threshold int    `json:"threshold"`
	PublicKey string `json:"public_key"` // X25519 (base64)
}

type joinMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	PublicKey string `json:"public_key"` // X25519 (base64)
}

type finalizeMessage struct {
	Type               string            `json:"type"`
	SessionID          string            `json:"session_id"`
	RSAPublicPEM       string            `json:"rsa_public_pem"`
	InitiatorPublicKey string            `json:"initiator_public_key"`
	Shares             map[string]string `json:"shares"` // pubkey_fingerprint -> encrypted share
}

func log(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorCyan+"[keygen] "+colorReset+format+"\n", args...)
}

func prompt(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorYellow+"→ "+colorReset+format+"\n", args...)
}

func sendMsg(label string, encoded string) {
	fmt.Fprintf(os.Stderr, colorGreen+colorBold+"Send this to the group chat:"+colorReset+"\n")
	fmt.Println(encoded)
	fmt.Fprintln(os.Stderr)
}

func RunKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	numParties := fs.Int("parties", 0, "total number of parties (initiator sets this)")
	threshold := fs.Int("threshold", 0, "signing threshold (default = parties)")
	outDir := fs.String("out-dir", ".", "output directory for share and public key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	if *numParties > 0 {
		// We are the initiator
		return runInitiator(scanner, *numParties, *threshold, *outDir)
	}

	// We are a joiner — wait for the init message
	return runJoiner(scanner, *outDir)
}

func runInitiator(scanner *bufio.Scanner, n, t int, outDir string) error {
	if t == 0 {
		t = n
	}
	if n < 2 || t < 2 || t > n {
		return fmt.Errorf("need 2 <= threshold(%d) <= parties(%d)", t, n)
	}

	// Generate our X25519 keypair
	privKey, err := mpc.GenerateX25519()
	if err != nil {
		return err
	}

	// Generate session ID
	sessionBytes := make([]byte, 16)
	rand.Read(sessionBytes)
	sessionID := base64.RawURLEncoding.EncodeToString(sessionBytes)

	log("Starting %d-of-%d keygen ceremony (session %s)", t, n, sessionID[:8])

	// Send INIT message
	initMsg := &initMessage{
		Type:      msgTypeInit,
		SessionID: sessionID,
		Parties:   n,
		Threshold: t,
		PublicKey: base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()),
	}
	sendMsg("INIT", encodeMsg(initMsg))

	// Collect JOIN messages from n-1 other parties
	joinerKeys := make([]*ecdh.PublicKey, 0, n-1)
	log("Waiting for %d join messages...", n-1)

	for len(joinerKeys) < n-1 {
		prompt("Paste a message from the group (%d/%d received):", len(joinerKeys), n-1)
		if !scanner.Scan() {
			return fmt.Errorf("unexpected end of input")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to decode as join message
		var join joinMessage
		if err := decodeMsg(line, &join); err != nil {
			log("(not a valid message, ignoring)")
			continue
		}
		if join.Type != msgTypeJoin {
			log("(ignoring %s message, waiting for join)", join.Type)
			continue
		}
		if join.SessionID != sessionID {
			log("(ignoring join from different session)")
			continue
		}

		pubBytes, _ := base64.StdEncoding.DecodeString(join.PublicKey)
		pub, err := ecdh.X25519().NewPublicKey(pubBytes)
		if err != nil {
			log("(invalid public key, ignoring)")
			continue
		}

		joinerKeys = append(joinerKeys, pub)
		log("Party %d joined (%d/%d)", len(joinerKeys)+1, len(joinerKeys), n-1)
	}

	log("All parties joined! Generating RSA-3072 key with e=3...")

	// Generate RSA key
	key, err := rsa3.GenerateKey()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	log("Key generated: %d-bit modulus", key.N.BitLen())

	// Generate threshold shares
	shares, err := mpc.SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, n, t)
	if err != nil {
		return err
	}

	// All party keys: [initiator, joiner1, joiner2, ...]
	allKeys := make([]*ecdh.PublicKey, n)
	allKeys[0] = privKey.PublicKey()
	copy(allKeys[1:], joinerKeys)

	// Encrypt each share for its recipient
	encryptedShares := make(map[string]string)
	for i, share := range shares {
		shareJSON, _ := json.Marshal(share)
		fp := pubKeyFingerprint(allKeys[i])
		encrypted, err := mpc.EncryptForParty(privKey, allKeys[i], shareJSON)
		if err != nil {
			return fmt.Errorf("encrypting share for party %d: %w", i+1, err)
		}
		encryptedShares[fp] = base64.StdEncoding.EncodeToString(encrypted)
	}

	// Save our own share
	sharePath := filepath.Join(outDir, fmt.Sprintf("share_%d.json", 1))
	if err := mpc.SaveThresholdShare(shares[0], sharePath); err != nil {
		return err
	}
	log("Your share (party 1) saved to %s (%d sub-shares)", sharePath, len(shares[0].Shares))

	// Save public key
	pubPEM := encodePubKeyPEM(key)
	os.WriteFile(filepath.Join(outDir, "public.pem"), []byte(pubPEM), 0644)
	log("Public key saved to %s", filepath.Join(outDir, "public.pem"))

	// Send FINALIZE message
	finMsg := &finalizeMessage{
		Type:               msgTypeFinalize,
		SessionID:          sessionID,
		RSAPublicPEM:       pubPEM,
		InitiatorPublicKey: base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()),
		Shares:             encryptedShares,
	}
	sendMsg("FINALIZE", encodeMsg(finMsg))

	// Clean up sensitive material
	key.D.SetInt64(0)
	key.P.SetInt64(0)
	key.Q.SetInt64(0)
	key.Lambda.SetInt64(0)

	log("Done! %d-of-%d keygen complete.", t, n)
	return nil
}

func runJoiner(scanner *bufio.Scanner, outDir string) error {
	// Generate our X25519 keypair
	privKey, err := mpc.GenerateX25519()
	if err != nil {
		return err
	}

	log("Joining keygen ceremony...")
	prompt("Paste the init message from the group:")

	// Wait for INIT message
	var init initMessage
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
		if init.Type != msgTypeInit {
			log("(not an init message, waiting for init)")
			continue
		}
		break
	}

	log("Joined %d-of-%d ceremony (session %s)", init.Threshold, init.Parties, init.SessionID[:8])

	// Send JOIN message
	joinMsg := &joinMessage{
		Type:      msgTypeJoin,
		SessionID: init.SessionID,
		PublicKey: base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()),
	}
	sendMsg("JOIN", encodeMsg(joinMsg))

	// Wait for FINALIZE message
	log("Waiting for finalize message...")
	prompt("Paste the finalize message from the group:")

	var fin finalizeMessage
	for {
		if !scanner.Scan() {
			return fmt.Errorf("unexpected end of input")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := decodeMsg(line, &fin); err != nil {
			log("(not a valid message, try again)")
			continue
		}
		if fin.Type != msgTypeFinalize {
			log("(not a finalize message, keep waiting)")
			continue
		}
		if fin.SessionID != init.SessionID {
			log("(wrong session, ignoring)")
			continue
		}
		break
	}

	// Find and decrypt our share
	myFP := pubKeyFingerprint(privKey.PublicKey())
	encryptedB64, ok := fin.Shares[myFP]
	if !ok {
		return fmt.Errorf("no share found for your key")
	}
	encrypted, _ := base64.StdEncoding.DecodeString(encryptedB64)

	initPubBytes, _ := base64.StdEncoding.DecodeString(fin.InitiatorPublicKey)
	initPub, err := ecdh.X25519().NewPublicKey(initPubBytes)
	if err != nil {
		return fmt.Errorf("invalid initiator key: %w", err)
	}

	shareJSON, err := mpc.DecryptFromParty(privKey, initPub, encrypted)
	if err != nil {
		return fmt.Errorf("decrypting share: %w", err)
	}

	var share mpc.ThresholdKeyShare
	if err := json.Unmarshal(shareJSON, &share); err != nil {
		return fmt.Errorf("parsing share: %w", err)
	}

	// Save share
	sharePath := filepath.Join(outDir, fmt.Sprintf("share_%d.json", share.PartyIndex))
	if err := mpc.SaveThresholdShare(&share, sharePath); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(outDir, "public.pem"), []byte(fin.RSAPublicPEM), 0644)

	log("Share saved to %s (party %d, %d-of-%d, %d sub-shares)",
		sharePath, share.PartyIndex, share.Threshold, share.NumParties, len(share.Shares))
	log("Public key saved to %s", filepath.Join(outDir, "public.pem"))
	log("Done!")

	return nil
}

func encodeMsg(v interface{}) string {
	data, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(data)
}

func decodeMsg(encoded string, v interface{}) error {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func pubKeyFingerprint(pub *ecdh.PublicKey) string {
	h := sha256.Sum256(pub.Bytes())
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func savePublicKeyPEM(path string, key *rsa3.KeyPair) error {
	pubKey := &rsa.PublicKey{N: key.N, E: key.E}
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

func encodePubKeyPEM(key *rsa3.KeyPair) string {
	pubKey := &rsa.PublicKey{N: key.N, E: key.E}
	derBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}
	return string(pem.EncodeToMemory(block))
}

