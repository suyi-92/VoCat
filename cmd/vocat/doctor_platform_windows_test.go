//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParsePEMachine(t *testing.T) {
	image := make([]byte, 0x90)
	copy(image[:2], "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:0x40], 0x80)
	copy(image[0x80:0x84], "PE\x00\x00")
	binary.LittleEndian.PutUint16(image[0x84:0x86], 0xaa64)
	machine, err := parsePEMachine(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	if machine != 0xaa64 || peMachineArchitecture(machine) != "arm64" {
		t.Fatalf("machine = 0x%04X/%s", machine, peMachineArchitecture(machine))
	}
}

func TestParsePEMachineRejectsInvalidImage(t *testing.T) {
	if _, err := parsePEMachine(bytes.NewReader(make([]byte, 64))); err == nil {
		t.Fatal("invalid PE image was accepted")
	}
}
