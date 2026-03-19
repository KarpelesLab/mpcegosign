package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// EnclaveConfig represents an EGo-compatible enclave.json.
type EnclaveConfig struct {
	Exe             string   `json:"exe"`
	Key             string   `json:"key"`
	Debug           bool     `json:"debug"`
	HeapSize        int      `json:"heapSize"`        // in MB
	ProductID       uint16   `json:"productID"`
	SecurityVersion uint16   `json:"securityVersion"`
	Mounts          []Mount  `json:"mounts,omitempty"`
	Files           []File   `json:"files,omitempty"`
	Env             []EnvVar `json:"env,omitempty"`
}

// Mount represents a filesystem mount configuration.
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Type     string `json:"type"`
	ReadOnly bool   `json:"readOnly"`
}

// File represents a file to embed in the enclave.
type File struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// EnvVar represents an environment variable.
type EnvVar struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	FromHost bool   `json:"fromHost,omitempty"`
}

// LoadConfig reads an enclave.json configuration file.
func LoadConfig(path string) (*EnclaveConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg EnclaveConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// HeapPages returns the heap size in 4096-byte pages.
func (c *EnclaveConfig) HeapPages() uint64 {
	return uint64(c.HeapSize) * 1024 * 1024 / 4096
}
