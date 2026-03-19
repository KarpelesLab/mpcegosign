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

// Protocol message types for group-chat keygen
const (
	msgTypeInit     = "keygen-init"
	msgTypeJoin     = "keygen-join"
	msgTypeFinalize = "keygen-finalize"
)

// InitMessage is broadcast by the initiator to the group.
type InitMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"` // random ID to correlate messages
	Parties   int    `json:"parties"`
	Threshold int    `json:"threshold"`
	PublicKey string `json:"public_key"` // initiator's X25519 public key (base64)
}

// JoinMessage is broadcast by each joiner to the group.
type JoinMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	PublicKey string `json:"public_key"` // joiner's X25519 public key (base64)
}

// FinalizeMessage is broadcast by the initiator after collecting all joins.
type FinalizeMessage struct {
	Type              string            `json:"type"`
	SessionID         string            `json:"session_id"`
	RSAPublicPEM      string            `json:"rsa_public_pem"`
	InitiatorPublicKey string           `json:"initiator_public_key"` // X25519 pubkey for decryption
	Shares            map[string]string `json:"shares"`              // X25519 pubkey hash -> encrypted share (base64)
}

// localState is saved between keygen steps.
type localState struct {
	SessionID          string `json:"session_id"`
	PrivateKey         string `json:"private_key"`                    // X25519 private key (base64)
	Role               string `json:"role"`                           // "initiator" or "joiner"
	Parties            int    `json:"parties"`
	Threshold          int    `json:"threshold"`
	InitiatorPublicKey string `json:"initiator_public_key,omitempty"` // saved by joiner
}

func RunKeygen(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "start":
			return RunKeygenStart(args[1:])
		case "join":
			return RunKeygenJoin(args[1:])
		case "finalize":
			return RunKeygenFinalize(args[1:])
		case "accept":
			return RunKeygenAccept(args[1:])
		}
	}
	return RunKeygenLocal(args)
}

// RunKeygenLocal generates all shares on one machine (ceremony mode).
func RunKeygenLocal(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	numParties := fs.Int("parties", 2, "number of parties (n)")
	threshold := fs.Int("threshold", 0, "signing threshold (t); default = n")
	outDir := fs.String("out-dir", ".", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	n := *numParties
	t := *threshold
	if t == 0 {
		t = n
	}
	if n < 2 || t < 2 || t > n {
		return fmt.Errorf("need 2 <= threshold <= parties (got t=%d, n=%d)", t, n)
	}

	fmt.Println("Generating RSA-3072 key with e=3...")
	key, err := rsa3.GenerateKey()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	if err := savePublicKeyPEM(filepath.Join(*outDir, "public.pem"), key); err != nil {
		return err
	}

	shares, err := mpc.SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, n, t)
	if err != nil {
		return err
	}

	for i, share := range shares {
		path := filepath.Join(*outDir, fmt.Sprintf("share_%d.json", i+1))
		if err := mpc.SaveThresholdShare(share, path); err != nil {
			return err
		}
		fmt.Printf("Share %d saved to %s (%d sub-shares)\n", i+1, path, len(share.Shares))
	}

	fmt.Printf("Done. %d-of-%d threshold. Any %d parties can sign.\n", t, n, t)
	return nil
}

// RunKeygenStart initiates a distributed keygen ceremony.
// Outputs an INIT message to post to the group chat.
func RunKeygenStart(args []string) error {
	fs := flag.NewFlagSet("keygen start", flag.ExitOnError)
	numParties := fs.Int("parties", 0, "total number of parties")
	threshold := fs.Int("threshold", 0, "signing threshold (default = parties)")
	outDir := fs.String("out-dir", ".", "directory for local state")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *numParties < 2 {
		return fmt.Errorf("--parties is required (>= 2)")
	}
	t := *threshold
	if t == 0 {
		t = *numParties
	}

	// Generate session ID
	sessionBytes := make([]byte, 16)
	if _, err := readRand(sessionBytes); err != nil {
		return err
	}
	sessionID := base64.RawURLEncoding.EncodeToString(sessionBytes)

	// Generate X25519 keypair
	privKey, err := mpc.GenerateX25519()
	if err != nil {
		return err
	}

	// Save local state
	state := &localState{
		SessionID:  sessionID,
		PrivateKey: base64.StdEncoding.EncodeToString(privKey.Bytes()),
		Role:       "initiator",
		Parties:    *numParties,
		Threshold:  t,
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	if err := saveLocalState(filepath.Join(*outDir, "keygen_state.json"), state); err != nil {
		return err
	}

	// Output INIT message
	initMsg := &InitMessage{
		Type:      msgTypeInit,
		SessionID: sessionID,
		Parties:   *numParties,
		Threshold: t,
		PublicKey: base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()),
	}

	encoded := encodeMessage(initMsg)
	fmt.Fprintf(os.Stderr, "\nPost this message to the group chat:\n\n")
	fmt.Println(encoded)
	fmt.Fprintf(os.Stderr, "\nWaiting for %d other parties to join.\n", *numParties-1)
	fmt.Fprintf(os.Stderr, "Once everyone has posted their join message, run:\n")
	fmt.Fprintf(os.Stderr, "  mpcegosign keygen finalize\n")

	return nil
}

// RunKeygenJoin joins an existing keygen ceremony.
// Reads the INIT message and outputs a JOIN message for the group.
func RunKeygenJoin(args []string) error {
	fs := flag.NewFlagSet("keygen join", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "directory for local state")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Paste the init message from the group chat:\n")
	initData := readLineFromStdin()

	var initMsg InitMessage
	if err := decodeMessage(initData, &initMsg); err != nil {
		return fmt.Errorf("invalid init message: %w", err)
	}
	if initMsg.Type != msgTypeInit {
		return fmt.Errorf("expected init message, got %s", initMsg.Type)
	}

	// Generate X25519 keypair
	privKey, err := mpc.GenerateX25519()
	if err != nil {
		return err
	}

	// Save local state (including initiator's pubkey for later decryption)
	state := &localState{
		SessionID:          initMsg.SessionID,
		PrivateKey:         base64.StdEncoding.EncodeToString(privKey.Bytes()),
		Role:               "joiner",
		Parties:            initMsg.Parties,
		Threshold:          initMsg.Threshold,
		InitiatorPublicKey: initMsg.PublicKey,
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	if err := saveLocalState(filepath.Join(*outDir, "keygen_state.json"), state); err != nil {
		return err
	}

	// Output JOIN message
	joinMsg := &JoinMessage{
		Type:      msgTypeJoin,
		SessionID: initMsg.SessionID,
		PublicKey: base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()),
	}

	encoded := encodeMessage(joinMsg)
	fmt.Fprintf(os.Stderr, "\nPost this message to the group chat:\n\n")
	fmt.Println(encoded)
	fmt.Fprintf(os.Stderr, "\nWait for the initiator to post the finalize message, then run:\n")
	fmt.Fprintf(os.Stderr, "  mpcegosign keygen accept\n")

	return nil
}

// RunKeygenFinalize collects JOIN messages and produces the FINALIZE message.
// The initiator runs this after all parties have posted their join messages.
func RunKeygenFinalize(args []string) error {
	fs := flag.NewFlagSet("keygen finalize", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "directory with local state")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load local state
	state, err := loadLocalState(filepath.Join(*outDir, "keygen_state.json"))
	if err != nil {
		return fmt.Errorf("loading state (did you run 'keygen start'?): %w", err)
	}
	if state.Role != "initiator" {
		return fmt.Errorf("only the initiator can finalize")
	}

	privKeyBytes, _ := base64.StdEncoding.DecodeString(state.PrivateKey)
	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	// Collect join messages
	expectedJoins := state.Parties - 1
	fmt.Fprintf(os.Stderr, "Paste %d join messages from the group chat (one per line):\n", expectedJoins)

	// Party list: initiator is party 1, joiners are 2..n in order
	partyKeys := make([]*ecdh.PublicKey, state.Parties)
	partyKeys[0] = privKey.PublicKey() // initiator is party 1

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for i := 0; i < expectedJoins; i++ {
		if !scanner.Scan() {
			return fmt.Errorf("expected %d join messages, got %d", expectedJoins, i)
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			i--
			continue
		}

		var joinMsg JoinMessage
		if err := decodeMessage(line, &joinMsg); err != nil {
			return fmt.Errorf("invalid join message #%d: %w", i+1, err)
		}
		if joinMsg.Type != msgTypeJoin {
			return fmt.Errorf("message #%d: expected join, got %s", i+1, joinMsg.Type)
		}
		if joinMsg.SessionID != state.SessionID {
			return fmt.Errorf("message #%d: session ID mismatch", i+1)
		}

		pubBytes, _ := base64.StdEncoding.DecodeString(joinMsg.PublicKey)
		pubKey, err := ecdh.X25519().NewPublicKey(pubBytes)
		if err != nil {
			return fmt.Errorf("message #%d: invalid public key: %w", i+1, err)
		}
		partyKeys[i+1] = pubKey
	}

	fmt.Fprintf(os.Stderr, "All %d join messages received.\n", expectedJoins)

	// Generate RSA key
	fmt.Fprintf(os.Stderr, "Generating RSA-3072 key with e=3...\n")
	key, err := rsa3.GenerateKey()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	// Generate threshold shares
	fmt.Fprintf(os.Stderr, "Splitting into %d-of-%d threshold shares...\n", state.Threshold, state.Parties)
	thresholdShares, err := mpc.SplitKeyThreshold(key.D, key.Lambda, key.N, key.E, state.Parties, state.Threshold)
	if err != nil {
		return err
	}

	// Encrypt each share for its recipient
	encryptedShares := make(map[string]string) // pubkey_hash -> encrypted_share
	for i, share := range thresholdShares {
		shareJSON, _ := json.Marshal(share)

		pubKeyHash := pubKeyFingerprint(partyKeys[i])

		encrypted, err := mpc.EncryptForParty(privKey, partyKeys[i], shareJSON)
		if err != nil {
			return fmt.Errorf("encrypting share for party %d: %w", i+1, err)
		}
		encryptedShares[pubKeyHash] = base64.StdEncoding.EncodeToString(encrypted)
	}

	// Save initiator's own share directly
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	sharePath := filepath.Join(*outDir, fmt.Sprintf("share_%d.json", 1))
	if err := mpc.SaveThresholdShare(thresholdShares[0], sharePath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Your share (party 1) saved to %s\n", sharePath)

	// Save public key
	pubPEM := encodePubKeyPEM(key)
	if err := os.WriteFile(filepath.Join(*outDir, "public.pem"), []byte(pubPEM), 0644); err != nil {
		return err
	}

	// Output FINALIZE message
	finMsg := &FinalizeMessage{
		Type:              msgTypeFinalize,
		SessionID:         state.SessionID,
		RSAPublicPEM:      pubPEM,
		InitiatorPublicKey: base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()),
		Shares:            encryptedShares,
	}

	encoded := encodeMessage(finMsg)
	fmt.Fprintf(os.Stderr, "\nPost this message to the group chat:\n\n")
	fmt.Println(encoded)

	// Clean up
	key.D.SetInt64(0)
	key.P.SetInt64(0)
	key.Q.SetInt64(0)
	key.Lambda.SetInt64(0)
	os.Remove(filepath.Join(*outDir, "keygen_state.json"))

	fmt.Fprintf(os.Stderr, "\nDone. Other parties should run: mpcegosign keygen accept\n")
	return nil
}

// RunKeygenAccept processes the FINALIZE message and extracts this party's share.
func RunKeygenAccept(args []string) error {
	fs := flag.NewFlagSet("keygen accept", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "directory with local state and output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load local state
	state, err := loadLocalState(filepath.Join(*outDir, "keygen_state.json"))
	if err != nil {
		return fmt.Errorf("loading state (did you run 'keygen join'?): %w", err)
	}

	privKeyBytes, _ := base64.StdEncoding.DecodeString(state.PrivateKey)
	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Paste the finalize message from the group chat:\n")
	finData := readLineFromStdin()

	var finMsg FinalizeMessage
	if err := decodeMessage(finData, &finMsg); err != nil {
		return fmt.Errorf("invalid finalize message: %w", err)
	}
	if finMsg.Type != msgTypeFinalize {
		return fmt.Errorf("expected finalize message, got %s", finMsg.Type)
	}
	if finMsg.SessionID != state.SessionID {
		return fmt.Errorf("session ID mismatch")
	}

	// Find our encrypted share by our public key fingerprint
	myFingerprint := pubKeyFingerprint(privKey.PublicKey())
	encryptedB64, ok := finMsg.Shares[myFingerprint]
	if !ok {
		return fmt.Errorf("no share found for your key (fingerprint: %s)", myFingerprint)
	}

	encrypted, _ := base64.StdEncoding.DecodeString(encryptedB64)

	// Get initiator's public key for ECDH decryption
	initPubBytes, _ := base64.StdEncoding.DecodeString(finMsg.InitiatorPublicKey)
	initPub, err := ecdh.X25519().NewPublicKey(initPubBytes)
	if err != nil {
		return fmt.Errorf("invalid initiator public key: %w", err)
	}

	// Decrypt our share
	shareJSON, err := mpc.DecryptFromParty(privKey, initPub, encrypted)
	if err != nil {
		return fmt.Errorf("decrypting share: %w", err)
	}

	var share mpc.ThresholdKeyShare
	if err := json.Unmarshal(shareJSON, &share); err != nil {
		return fmt.Errorf("parsing share: %w", err)
	}

	// Save share
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	sharePath := filepath.Join(*outDir, fmt.Sprintf("share_%d.json", share.PartyIndex))
	if err := mpc.SaveThresholdShare(&share, sharePath); err != nil {
		return err
	}

	// Save RSA public key
	if err := os.WriteFile(filepath.Join(*outDir, "public.pem"), []byte(finMsg.RSAPublicPEM), 0644); err != nil {
		return err
	}

	// Clean up state
	os.Remove(filepath.Join(*outDir, "keygen_state.json"))

	fmt.Fprintf(os.Stderr, "Share saved to %s (party %d, %d-of-%d, %d sub-shares)\n",
		sharePath, share.PartyIndex, share.Threshold, share.NumParties, len(share.Shares))
	fmt.Fprintf(os.Stderr, "Public key saved to %s\n", filepath.Join(*outDir, "public.pem"))

	return nil
}

// Helper: we need the initiator's public key in accept. Let me add it to FinalizeMessage.
// I'll refactor: add InitiatorPublicKey to FinalizeMessage and save initiator pubkey during join.

func encodeMessage(v interface{}) string {
	data, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(data)
}

func decodeMessage(encoded string, v interface{}) error {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func readLineFromStdin() string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func pubKeyFingerprint(pub *ecdh.PublicKey) string {
	h := sha256.Sum256(pub.Bytes())
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func readRand(b []byte) (int, error) {
	return rand.Read(b)
}

func saveLocalState(path string, state *localState) error {
	data, _ := json.MarshalIndent(state, "", "  ")
	return os.WriteFile(path, data, 0600)
}

func loadLocalState(path string) (*localState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state localState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
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

