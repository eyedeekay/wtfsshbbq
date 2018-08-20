package wtfsshbbq

import (
	"log"
	"testing"
)

func TestEd25519(t *testing.T) {
	log.Println("Generating a key of type:", "ed25519", "of length:", "32")
	if KeyRing, KeyErr := NewSSHKeyRing(
		SetType("ed25519"),
		SetLength(32),
		SetPath("keys/test_ed25519"),
		SetRounds(1000),
		SetHashType("sha256"),
	); KeyErr != nil {
		log.Fatal(KeyErr)
	} else {
		KeyRing.SaveRing()
	}
	log.Println("Key generated")
}

func TestRSA(t *testing.T) {
	log.Println("Generating a key of type:", "rsa", "of length:", "4096")
	if KeyRing, KeyErr := NewSSHKeyRing(
		SetType("rsa"),
		SetLength(4096),
		SetPath("keys/test_rsa"),
		SetRounds(1000),
		SetHashType("sha256"),
	); KeyErr != nil {
		log.Fatal(KeyErr)
	} else {
		KeyRing.SaveRing()
	}
	log.Println("Key generated")
}
