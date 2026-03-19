package sgx

import (
	"encoding/binary"
	"testing"
)

func TestECREATE(t *testing.T) {
	m := NewMeasurement()
	m.ECREATE(1, 0x10000)
	hash := m.Sum()
	// Just verify it produces a deterministic hash
	if hash == [32]byte{} {
		t.Error("ECREATE produced zero hash")
	}

	// Same input should produce same hash
	m2 := NewMeasurement()
	m2.ECREATE(1, 0x10000)
	if m2.Sum() != hash {
		t.Error("ECREATE not deterministic")
	}

	// Different size should produce different hash
	m3 := NewMeasurement()
	m3.ECREATE(1, 0x20000)
	if m3.Sum() == hash {
		t.Error("different enclave size should produce different hash")
	}
}

func TestEADD(t *testing.T) {
	m := NewMeasurement()
	m.ECREATE(1, 0x10000)
	hash1 := m.Sum()

	m2 := NewMeasurement()
	m2.ECREATE(1, 0x10000)
	m2.EADD(0x1000, SecinfoR|SecinfoREG)
	hash2 := m2.Sum()

	if hash1 == hash2 {
		t.Error("EADD should change hash")
	}
}

func TestEEXTEND(t *testing.T) {
	m := NewMeasurement()
	m.ECREATE(1, 0x10000)
	m.EADD(0x1000, SecinfoR|SecinfoREG)

	data := make([]byte, 256)
	data[0] = 0x42
	m.EEXTEND(0x1000, 0, data)
	hash1 := m.Sum()

	// Different data should produce different hash
	m2 := NewMeasurement()
	m2.ECREATE(1, 0x10000)
	m2.EADD(0x1000, SecinfoR|SecinfoREG)
	data2 := make([]byte, 256)
	data2[0] = 0x43
	m2.EEXTEND(0x1000, 0, data2)
	hash2 := m2.Sum()

	if hash1 == hash2 {
		t.Error("different data should produce different EEXTEND hash")
	}
}

func TestAddPage(t *testing.T) {
	// Test that AddPage with extend=true produces EADD + 16 EEXTEND blocks
	m1 := NewMeasurement()
	m1.ECREATE(1, 0x10000)

	data := make([]byte, PageSize)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	m1.AddPage(0x1000, SecinfoR|SecinfoREG, data, true)
	hash1 := m1.Sum()

	// Manual equivalent
	m2 := NewMeasurement()
	m2.ECREATE(1, 0x10000)
	m2.EADD(0x1000, SecinfoR|SecinfoREG)
	for i := 0; i < PageSize; i += 256 {
		m2.EEXTEND(0x1000, i, data[i:i+256])
	}
	hash2 := m2.Sum()

	if hash1 != hash2 {
		t.Error("AddPage should produce same result as manual EADD + EEXTEND")
	}
}

func TestAddPageWithPattern(t *testing.T) {
	m := NewMeasurement()
	m.ECREATE(1, 0x10000)
	m.AddPageWithPattern(0x1000, SecinfoR|SecinfoW|SecinfoREG, 0xCCCCCCCC)
	hash := m.Sum()

	// Verify against manual construction
	m2 := NewMeasurement()
	m2.ECREATE(1, 0x10000)
	m2.EADD(0x1000, SecinfoR|SecinfoW|SecinfoREG)
	pageData := make([]byte, PageSize)
	for i := 0; i < PageSize; i += 4 {
		binary.LittleEndian.PutUint32(pageData[i:], 0xCCCCCCCC)
	}
	for i := 0; i < PageSize; i += 256 {
		m2.EEXTEND(0x1000, i, pageData[i:i+256])
	}
	hash2 := m2.Sum()

	if hash != hash2 {
		t.Error("AddPageWithPattern should match manual construction")
	}
}
