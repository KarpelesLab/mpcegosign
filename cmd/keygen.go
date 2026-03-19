package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/magicaltux/mpcegosign/pkg/mpc"
	"github.com/magicaltux/mpcegosign/pkg/rsa3"
)

// KeygenMessage is the JSON structure exchanged between parties during keygen.
type KeygenMessage struct {
	Type       string `json:"type"`        // "contribution", "share", or "keygen-single"
	Version    int    `json:"version"`
	PartyIndex int    `json:"party_index"` // 1-based
	NumParties int    `json:"num_parties"`
	Data       string `json:"data"`        // base64-encoded payload
}

// ContributionPayload is what non-coordinator parties send in Round 1.
type ContributionPayload struct {
	Randomness string `json:"randomness"` // base64 big-endian, random value
}

// SharePayload is what the coordinator sends back in Round 2.
type SharePayload struct {
	Modulus        string `json:"modulus"`          // base64 big-endian
	PublicExponent int    `json:"public_exponent"`
	ShareValue     string `json:"share_value"`     // base64 big-endian
	PublicKeyPEM   string `json:"public_key_pem"`
}

func RunKeygen(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "contribute":
			return RunKeygenContribute(args[1:])
		case "finalize":
			return RunKeygenFinalize(args[1:])
		case "accept":
			return RunKeygenAccept(args[1:])
		}
	}

	// Original all-in-one keygen (for local/ceremony use)
	return RunKeygenLocal(args)
}

// RunKeygenLocal generates all shares on one machine (ceremony mode).
func RunKeygenLocal(args []string) error {
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

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	pubKeyPath := filepath.Join(*outDir, "public.pem")
	if err := savePublicKeyPEM(pubKeyPath, key); err != nil {
		return fmt.Errorf("saving public key: %w", err)
	}
	fmt.Printf("Public key saved to %s\n", pubKeyPath)

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

// RunKeygenContribute generates a random contribution for distributed keygen.
// Each non-coordinator party runs this, then sends the output message to the coordinator.
//
// Usage: mpcegosign keygen contribute --parties N --party I --out contribution.msg
func RunKeygenContribute(args []string) error {
	fs := flag.NewFlagSet("keygen contribute", flag.ExitOnError)
	numParties := fs.Int("parties", 0, "total number of parties")
	partyIndex := fs.Int("party", 0, "this party's index (1-based)")
	outPath := fs.String("out", "", "output message file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *numParties < 2 || *partyIndex < 1 || *partyIndex > *numParties {
		return fmt.Errorf("--parties (>=2) and --party (1..N) are required")
	}

	// Generate 384 bytes (3072 bits) of randomness
	randomBytes := make([]byte, 384)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Errorf("generating randomness: %w", err)
	}

	payload := &ContributionPayload{
		Randomness: base64.StdEncoding.EncodeToString(randomBytes),
	}
	payloadJSON, _ := json.Marshal(payload)

	msg := &KeygenMessage{
		Type:       "contribution",
		Version:    1,
		PartyIndex: *partyIndex,
		NumParties: *numParties,
		Data:       base64.StdEncoding.EncodeToString(payloadJSON),
	}

	msgJSON, _ := json.Marshal(msg)
	encoded := base64.StdEncoding.EncodeToString(msgJSON)

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(encoded+"\n"), 0600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Contribution written to %s\n", *outPath)
		fmt.Fprintf(os.Stderr, "Send this message to the coordinator (party that will run 'keygen finalize')\n")
	} else {
		fmt.Println(encoded)
		fmt.Fprintln(os.Stderr, "\nCopy the message above and send to the coordinator.")
	}

	// Save the randomness locally — it's needed to derive the share later
	localPath := fmt.Sprintf("keygen_local_%d.json", *partyIndex)
	localData, _ := json.Marshal(map[string]string{
		"randomness": payload.Randomness,
	})
	if err := os.WriteFile(localPath, localData, 0600); err != nil {
		return fmt.Errorf("saving local state: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Local keygen state saved to %s (keep this secure, needed for 'keygen accept')\n", localPath)

	return nil
}

// RunKeygenFinalize is run by the coordinator after collecting all contributions.
// It generates the RSA key, incorporates contributions, and outputs share messages.
//
// Usage: mpcegosign keygen finalize --party I --contributions c1.msg,c2.msg,... --out-dir DIR
func RunKeygenFinalize(args []string) error {
	fs := flag.NewFlagSet("keygen finalize", flag.ExitOnError)
	partyIndex := fs.Int("party", 0, "coordinator's party index (1-based)")
	contribList := fs.String("contributions", "", "comma-separated contribution message files")
	outDir := fs.String("out-dir", ".", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *partyIndex < 1 || *contribList == "" {
		return fmt.Errorf("--party and --contributions are required")
	}

	// Parse contribution files
	contribPaths := splitCSV(*contribList)
	contributions := make(map[int]*big.Int) // party_index -> randomness

	var numParties int
	for _, path := range contribPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		msgJSON, err := base64.StdEncoding.DecodeString(string(trimSpace(data)))
		if err != nil {
			return fmt.Errorf("decoding message from %s: %w", path, err)
		}
		var msg KeygenMessage
		if err := json.Unmarshal(msgJSON, &msg); err != nil {
			return fmt.Errorf("parsing message from %s: %w", path, err)
		}
		if msg.Type != "contribution" {
			return fmt.Errorf("%s: expected contribution message, got %s", path, msg.Type)
		}
		if msg.PartyIndex == *partyIndex {
			return fmt.Errorf("%s: contribution is from the coordinator (party %d); coordinator doesn't send contributions to itself", path, msg.PartyIndex)
		}

		payloadJSON, _ := base64.StdEncoding.DecodeString(msg.Data)
		var payload ContributionPayload
		json.Unmarshal(payloadJSON, &payload)

		randomBytes, _ := base64.StdEncoding.DecodeString(payload.Randomness)
		contributions[msg.PartyIndex] = new(big.Int).SetBytes(randomBytes)
		numParties = msg.NumParties
	}

	if numParties < 2 {
		return fmt.Errorf("need at least 2 parties")
	}

	// Check we have contributions from all non-coordinator parties
	for i := 1; i <= numParties; i++ {
		if i == *partyIndex {
			continue
		}
		if _, ok := contributions[i]; !ok {
			return fmt.Errorf("missing contribution from party %d", i)
		}
	}

	fmt.Fprintf(os.Stderr, "Generating RSA-3072 key with e=3...\n")
	key, err := rsa3.GenerateKey()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Key generated: %d-bit modulus\n", key.N.BitLen())

	// Compute shares:
	// For each non-coordinator party i: share_i = contribution_i mod lambda
	// For coordinator: share_coord = (d - sum(share_i for i != coord)) mod lambda
	shares := make(map[int]*big.Int)
	sumOthers := new(big.Int)

	for i := 1; i <= numParties; i++ {
		if i == *partyIndex {
			continue
		}
		share := new(big.Int).Mod(contributions[i], key.Lambda)
		shares[i] = share
		sumOthers.Add(sumOthers, share)
	}

	// Coordinator's share
	coordShare := new(big.Int).Sub(key.D, sumOthers)
	coordShare.Mod(coordShare, key.Lambda)
	shares[*partyIndex] = coordShare

	// Save public key
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	pubKeyPath := filepath.Join(*outDir, "public.pem")
	if err := savePublicKeyPEM(pubKeyPath, key); err != nil {
		return fmt.Errorf("saving public key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Public key saved to %s\n", pubKeyPath)

	// Save coordinator's own share
	coordShareFile := &mpc.KeyShare{
		Version:        1,
		PartyIndex:     *partyIndex,
		NumParties:     numParties,
		Modulus:        base64.StdEncoding.EncodeToString(key.N.Bytes()),
		PublicExponent: key.E,
		Share:          base64.StdEncoding.EncodeToString(coordShare.Bytes()),
	}
	coordPath := filepath.Join(*outDir, fmt.Sprintf("share_%d.json", *partyIndex))
	if err := mpc.SaveShare(coordShareFile, coordPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Coordinator share saved to %s\n", coordPath)

	// Generate public key PEM for embedding in messages
	pubPEM := encodePubKeyPEM(key)

	// Output share messages for other parties
	for i := 1; i <= numParties; i++ {
		if i == *partyIndex {
			continue
		}

		payload := &SharePayload{
			Modulus:        base64.StdEncoding.EncodeToString(key.N.Bytes()),
			PublicExponent: key.E,
			ShareValue:     base64.StdEncoding.EncodeToString(shares[i].Bytes()),
			PublicKeyPEM:   pubPEM,
		}
		payloadJSON, _ := json.Marshal(payload)

		msg := &KeygenMessage{
			Type:       "share",
			Version:    1,
			PartyIndex: i,
			NumParties: numParties,
			Data:       base64.StdEncoding.EncodeToString(payloadJSON),
		}
		msgJSON, _ := json.Marshal(msg)
		encoded := base64.StdEncoding.EncodeToString(msgJSON)

		msgPath := filepath.Join(*outDir, fmt.Sprintf("msg_to_party_%d.txt", i))
		if err := os.WriteFile(msgPath, []byte(encoded+"\n"), 0644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Share message for party %d written to %s\n", i, msgPath)
	}

	// Clear sensitive material
	key.D.SetInt64(0)
	key.P.SetInt64(0)
	key.Q.SetInt64(0)
	key.Lambda.SetInt64(0)

	fmt.Fprintf(os.Stderr, "\nDone. Send each msg_to_party_N.txt to the respective party.\n")
	fmt.Fprintf(os.Stderr, "They should run: mpcegosign keygen accept --msg <message_file> --out share.json\n")
	return nil
}

// RunKeygenAccept imports a share from a coordinator's message.
//
// Usage: mpcegosign keygen accept --msg share.msg --out share.json
func RunKeygenAccept(args []string) error {
	fs := flag.NewFlagSet("keygen accept", flag.ExitOnError)
	msgPath := fs.String("msg", "", "path to share message file")
	outPath := fs.String("out", "", "output share file (default: share_N.json)")
	outDir := fs.String("out-dir", ".", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *msgPath == "" {
		return fmt.Errorf("--msg is required")
	}

	data, err := os.ReadFile(*msgPath)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	msgJSON, err := base64.StdEncoding.DecodeString(string(trimSpace(data)))
	if err != nil {
		return fmt.Errorf("decoding message: %w", err)
	}

	var msg KeygenMessage
	if err := json.Unmarshal(msgJSON, &msg); err != nil {
		return fmt.Errorf("parsing message: %w", err)
	}

	if msg.Type != "share" {
		return fmt.Errorf("expected share message, got %s", msg.Type)
	}

	payloadJSON, _ := base64.StdEncoding.DecodeString(msg.Data)
	var payload SharePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return fmt.Errorf("parsing share payload: %w", err)
	}

	// Save share
	share := &mpc.KeyShare{
		Version:        1,
		PartyIndex:     msg.PartyIndex,
		NumParties:     msg.NumParties,
		Modulus:        payload.Modulus,
		PublicExponent: payload.PublicExponent,
		Share:          payload.ShareValue,
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}

	sharePath := *outPath
	if sharePath == "" {
		sharePath = filepath.Join(*outDir, fmt.Sprintf("share_%d.json", msg.PartyIndex))
	}
	if err := mpc.SaveShare(share, sharePath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Share saved to %s (party %d of %d)\n", sharePath, msg.PartyIndex, msg.NumParties)

	// Save public key
	pubKeyPath := filepath.Join(*outDir, "public.pem")
	if err := os.WriteFile(pubKeyPath, []byte(payload.PublicKeyPEM), 0644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Public key saved to %s\n", pubKeyPath)

	// Clean up local keygen state if it exists
	localPath := fmt.Sprintf("keygen_local_%d.json", msg.PartyIndex)
	os.Remove(localPath)

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

func encodePubKeyPEM(key *rsa3.KeyPair) string {
	pubKey := &rsa.PublicKey{N: key.N, E: key.E}
	derBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block))
}

func splitCSV(s string) []string {
	var result []string
	for _, part := range split(s, ',') {
		trimmed := trimString(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimString(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func trimSpace(b []byte) []byte {
	return []byte(trimString(string(b)))
}
